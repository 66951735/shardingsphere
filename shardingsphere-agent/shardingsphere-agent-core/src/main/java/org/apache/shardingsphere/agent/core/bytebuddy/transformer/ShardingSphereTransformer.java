/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.shardingsphere.agent.core.bytebuddy.transformer;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.bytebuddy.agent.builder.AgentBuilder.Transformer;
import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.DynamicType.Builder;
import net.bytebuddy.implementation.FieldAccessor;
import net.bytebuddy.implementation.MethodDelegation;
import net.bytebuddy.implementation.SuperMethodCall;
import net.bytebuddy.jar.asm.Opcodes;
import net.bytebuddy.matcher.ElementMatchers;
import net.bytebuddy.utility.JavaModule;
import org.apache.shardingsphere.agent.api.advice.AdviceTargetObject;
import org.apache.shardingsphere.agent.api.advice.ClassStaticMethodAroundAdvice;
import org.apache.shardingsphere.agent.api.advice.ConstructorAdvice;
import org.apache.shardingsphere.agent.api.advice.InstanceMethodAroundAdvice;
import org.apache.shardingsphere.agent.api.point.ClassStaticMethodPoint;
import org.apache.shardingsphere.agent.api.point.ConstructorPoint;
import org.apache.shardingsphere.agent.api.point.InstanceMethodPoint;
import org.apache.shardingsphere.agent.api.point.PluginInterceptorPoint;
import org.apache.shardingsphere.agent.core.plugin.PluginLoader;
import org.apache.shardingsphere.agent.core.plugin.interceptor.ClassStaticMethodAroundInterceptor;
import org.apache.shardingsphere.agent.core.plugin.interceptor.ConstructorInterceptor;
import org.apache.shardingsphere.agent.core.plugin.interceptor.InstanceMethodAroundInterceptor;
import org.apache.shardingsphere.agent.core.plugin.interceptor.compose.ComposeClassStaticMethodAroundInterceptor;
import org.apache.shardingsphere.agent.core.plugin.interceptor.compose.ComposeConstructorInterceptor;
import org.apache.shardingsphere.agent.core.plugin.interceptor.compose.ComposeInstanceMethodAroundInterceptor;

import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * ShardingSphere transformer.
 */
@RequiredArgsConstructor
@Slf4j
public final class ShardingSphereTransformer implements Transformer {
    
    private static final String EXTRA_DATA = "_$EXTRA_DATA$_";
    
    private final PluginLoader pluginLoader;
    
    @Override
    public Builder<?> transform(final Builder<?> builder, final TypeDescription typeDescription, final ClassLoader classLoader, final JavaModule module) {
        if (pluginLoader.containsType(typeDescription)) {
            Builder<?> result = builder;
            result = result.defineField(EXTRA_DATA, Object.class, Opcodes.ACC_PRIVATE | Opcodes.ACC_VOLATILE)
                    .implement(AdviceTargetObject.class)
                    .intercept(FieldAccessor.ofField(EXTRA_DATA));
            PluginInterceptorPoint pluginInterceptorPoint = pluginLoader.loadPluginInterceptorPoint(typeDescription);
            result = interceptorConstructorPoint(typeDescription, pluginInterceptorPoint.getConstructorPoints(), result);
            result = interceptorClassStaticMethodPoint(typeDescription, pluginInterceptorPoint.getClassStaticMethodPoints(), result);
            result = interceptorInstanceMethodPoint(typeDescription, pluginInterceptorPoint.getInstanceMethodPoints(), result);
            return result;
        }
        return builder;
    }
    
    private Builder<?> interceptorConstructorPoint(final TypeDescription description, final List<ConstructorPoint> constructorPoints, final Builder<?> builder) {
        List<ShardingSphereTransformationPoint<? extends ConstructorInterceptor>> constructorAdviceComposePoints = description.getDeclaredMethods().stream()
                .filter(MethodDescription::isConstructor)
                .map(methodDescription -> {
                    List<ConstructorPoint> constructorPointList = constructorPoints.stream().filter(point -> point.getMatcher().matches(methodDescription)).collect(Collectors.toList());
                    if (constructorPointList.isEmpty()) {
                        return null;
                    }
                    if (constructorPointList.size() == 1) {
                        return new ShardingSphereTransformationPoint<>(methodDescription, new ConstructorInterceptor(pluginLoader.getOrCreateInstance(constructorPointList.get(0).getAdvice())));
                    } else {
                        List<ConstructorAdvice> constructorAdvices = constructorPointList.stream()
                                .map(ConstructorPoint::getAdvice)
                                .map(advice -> (ConstructorAdvice) pluginLoader.getOrCreateInstance(advice))
                                .collect(Collectors.toList());
                        return new ShardingSphereTransformationPoint<>(methodDescription, new ComposeConstructorInterceptor(constructorAdvices));
                    }
                })
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
        Builder<?> result = builder;
        for (ShardingSphereTransformationPoint<? extends ConstructorInterceptor> each : constructorAdviceComposePoints) {
            try {
                result = result.constructor(ElementMatchers.is(each.getDescription()))
                        .intercept(SuperMethodCall.INSTANCE.andThen(MethodDelegation.withDefaultConfiguration().to(each.getInterceptor())));
                // CHECKSTYLE:OFF
            } catch (final Throwable ex) {
                // CHECKSTYLE:ON
                log.error("Failed to load advice class: {}", description.getTypeName(), ex);
            }
        }
        return result;
    }
    
    private Builder<?> interceptorClassStaticMethodPoint(final TypeDescription description, final List<ClassStaticMethodPoint> classStaticMethodAroundPoints, final Builder<?> builder) {
        List<ShardingSphereTransformationPoint<?>> classStaticMethodAdvicePoints = description.getDeclaredMethods().stream()
                .filter(each -> each.isStatic() && !(each.isAbstract() || each.isSynthetic()))
                .map(methodDescription -> getStaticMethodPoint(methodDescription, classStaticMethodAroundPoints))
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
        Builder<?> result = builder;
        for (ShardingSphereTransformationPoint<?> each : classStaticMethodAdvicePoints) {
            try {
                result = result.method(ElementMatchers.is(each.getDescription()))
                        .intercept(MethodDelegation.withDefaultConfiguration().to(each.getInterceptor()));
                // CHECKSTYLE:OFF
            } catch (final Throwable ex) {
                // CHECKSTYLE:ON
                log.error("Failed to load advice class: {}", description.getTypeName(), ex);
            }
        }
        return result;
    }
    
    private ShardingSphereTransformationPoint<?> getStaticMethodPoint(final MethodDescription.InDefinedShape methodDescription, final List<ClassStaticMethodPoint> classStaticMethodAroundPoints) {
        List<ClassStaticMethodPoint> classStaticMethodPoints = classStaticMethodAroundPoints.stream().filter(point -> point.getMatcher().matches(methodDescription)).collect(Collectors.toList());
        if (classStaticMethodPoints.isEmpty()) {
            return null;
        }
        if (classStaticMethodPoints.size() == 1) {
            return new ShardingSphereTransformationPoint<>(methodDescription, new ClassStaticMethodAroundInterceptor(pluginLoader.getOrCreateInstance(classStaticMethodPoints.get(0).getAdvice())));
        } else {
            Collection<ClassStaticMethodAroundAdvice> classStaticMethodAroundAdvices = new LinkedList<>();
            for (ClassStaticMethodPoint point : classStaticMethodPoints) {
                if (null != point.getAdvice()) {
                    classStaticMethodAroundAdvices.add(pluginLoader.getOrCreateInstance(point.getAdvice()));
                }
            }
            return new ShardingSphereTransformationPoint<>(methodDescription, new ComposeClassStaticMethodAroundInterceptor(classStaticMethodAroundAdvices));
        }
    }
    
    private Builder<?> interceptorInstanceMethodPoint(final TypeDescription description, final List<InstanceMethodPoint> instanceMethodAroundPoints, final Builder<?> builder) {
        List<ShardingSphereTransformationPoint<?>> instanceMethodAdviceComposePoints = description.getDeclaredMethods().stream()
                .filter(each -> !(each.isAbstract() || each.isSynthetic()))
                .map(methodDescription -> getInstanceMethodPoint(methodDescription, instanceMethodAroundPoints))
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
        Builder<?> result = builder;
        for (ShardingSphereTransformationPoint<?> each : instanceMethodAdviceComposePoints) {
            try {
                result = result.method(ElementMatchers.is(each.getDescription()))
                        .intercept(MethodDelegation.withDefaultConfiguration().to(each.getInterceptor()));
                // CHECKSTYLE:OFF
            } catch (final Throwable ex) {
                // CHECKSTYLE:ON
                log.error("Failed to load advice class: {}", description.getTypeName(), ex);
            }
        }
        return result;
    }
    
    private ShardingSphereTransformationPoint<?> getInstanceMethodPoint(final MethodDescription.InDefinedShape methodDescription, final List<InstanceMethodPoint> instanceMethodAroundPoints) {
        List<InstanceMethodPoint> instanceMethodPoints = instanceMethodAroundPoints.stream().filter(point -> point.getMatcher().matches(methodDescription)).collect(Collectors.toList());
        if (instanceMethodPoints.isEmpty()) {
            return null;
        }
        if (instanceMethodPoints.size() == 1) {
            return new ShardingSphereTransformationPoint<>(methodDescription, new InstanceMethodAroundInterceptor(pluginLoader.getOrCreateInstance(instanceMethodPoints.get(0).getAdvice())));
        } else {
            Collection<InstanceMethodAroundAdvice> instanceMethodAroundAdvices = new LinkedList<>();
            for (InstanceMethodPoint point : instanceMethodPoints) {
                if (null != point.getAdvice()) {
                    instanceMethodAroundAdvices.add(pluginLoader.getOrCreateInstance(point.getAdvice()));
                }
            }
            return new ShardingSphereTransformationPoint<>(methodDescription, new ComposeInstanceMethodAroundInterceptor(instanceMethodAroundAdvices));
        }
    }
}
