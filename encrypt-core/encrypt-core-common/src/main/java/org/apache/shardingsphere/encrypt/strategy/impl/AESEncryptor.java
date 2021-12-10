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

package org.apache.shardingsphere.encrypt.strategy.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Preconditions;
import lombok.Getter;
import lombok.Setter;
import lombok.SneakyThrows;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.shardingsphere.encrypt.metadata.AESKeyMetaData;
import org.apache.shardingsphere.encrypt.strategy.spi.Encryptor;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Collectors;

/**
 * AES encryptor.
 */
@Getter
@Setter
public final class AESEncryptor implements Encryptor {

    private static final String AES_KEY = "aes.key.value";

    private static final ObjectMapper objectMapper = new ObjectMapper()
            .configure(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY, true);

    private Properties properties = new Properties();

    @Override
    public String getType() {
        return "AES";
    }

    @Override
    public void init() {
    }

    @Override
    @SneakyThrows
    public String encrypt(final Object plaintext) {
        if (null == plaintext) {
            return null;
        }
        byte[] result = getCipher(Cipher.ENCRYPT_MODE, null).doFinal(StringUtils.getBytesUtf8(String.valueOf(plaintext)));
        return getKeyVersion() + ":" + Base64.encodeBase64String(result);
    }

    @Override
    @SneakyThrows
    public Object decrypt(final String ciphertext) {
        if (null == ciphertext) {
            return null;
        }
        byte[] result = getCipher(Cipher.DECRYPT_MODE, ciphertext).doFinal(Base64.decodeBase64(ciphertext));
        return new String(result, StandardCharsets.UTF_8);
    }

    @Override
    @SneakyThrows
    public Object decrypt(final String ciphertext, final Class<?> type) {
        if (null == ciphertext) {
            return null;
        }
        String[] cipherInfo = ciphertext.split(":");
        byte[] result = getCipher(Cipher.DECRYPT_MODE, ciphertext).doFinal(Base64.decodeBase64(cipherInfo.length == 2 ? cipherInfo[1] : cipherInfo[0]));
        String finalResult = new String(result, StandardCharsets.UTF_8);
        if (type == java.sql.Timestamp.class) {
            try {
                SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                return simpleDateFormat.parse(finalResult);
            } catch (ParseException e) {
                // do nothing;
            }
        }
        return finalResult;
    }

    private Cipher getCipher(final int decryptMode, final String ciphertext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Preconditions.checkArgument(properties.containsKey(AES_KEY), "No available secret key for `%s`.", AESEncryptor.class.getName());
        Cipher result = Cipher.getInstance(getType());
        result.init(decryptMode, new SecretKeySpec(createSecretKey(ciphertext), getType()));
        return result;
    }

    private byte[] createSecretKey(final String ciphertext) {
        List<AESKeyMetaData> candidateKeys = getCandidateKeys();
        if (ciphertext == null) {
            return Arrays.copyOf(DigestUtils.sha1(candidateKeys.get(0).getKey()), 16);
        }
        Map<String, String> candidateKeysMap = candidateKeys.stream().collect(Collectors.toMap(AESKeyMetaData::getVersion, AESKeyMetaData::getKey, (key1, key2) -> key2));
        String[] cipherInfo = ciphertext.split(":");
        String currentVersion = "";
        if (cipherInfo.length == 2) {
            currentVersion = cipherInfo[0];
        }
        Preconditions.checkArgument(candidateKeysMap.containsKey(currentVersion), String.format("No available secret key for version `%s`.", currentVersion));
        return Arrays.copyOf(DigestUtils.sha1(candidateKeysMap.get(currentVersion)), 16);
    }

    private String getKeyVersion() {
        return getCandidateKeys().get(0).getVersion();
    }

    private List<AESKeyMetaData> getCandidateKeys() {
        Preconditions.checkArgument(null != properties.get(AES_KEY), String.format("%s can not be null.", AES_KEY));
        String keys = properties.get(AES_KEY).toString();
        List<AESKeyMetaData> candidateKeys = null;
        try {
            candidateKeys = objectMapper.readValue(keys, new TypeReference<List<AESKeyMetaData>>() {
            });
        } catch (JsonProcessingException e) {
            // do nothing
            e.printStackTrace();
        }
        Preconditions.checkArgument(null != candidateKeys && !candidateKeys.isEmpty(), String.format("%s can not be converted to a valid key.", AES_KEY));
        Collections.sort(candidateKeys, (o1, o2) -> o2.getVersion().compareTo(o1.getVersion()));
        return candidateKeys;
    }
}
