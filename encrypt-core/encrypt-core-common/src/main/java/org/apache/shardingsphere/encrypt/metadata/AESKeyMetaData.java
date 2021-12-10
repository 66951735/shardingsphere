package org.apache.shardingsphere.encrypt.metadata;

import lombok.Data;

/**
 * @author lisheng
 * @date 2021/12/10 12:06
 */
@Data
public class AESKeyMetaData {
    private String version;
    private String key;
    private Long timestamp;
}
