package org.opensingular.dbuserprovider.persistence;

import lombok.extern.jbosslog.JBossLog;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.binary.StringUtils;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.NotImplementedException;
import org.mindrot.jbcrypt.BCrypt;
import org.opensingular.dbuserprovider.DBUserStorageException;
import org.opensingular.dbuserprovider.model.QueryConfigurations;
import org.opensingular.dbuserprovider.util.PBKDF2SHA256HashingUtil;
import org.opensingular.dbuserprovider.util.PagingUtil;
import org.opensingular.dbuserprovider.util.PagingUtil.Pageable;

import javax.sql.DataSource;
import java.io.ByteArrayOutputStream;
import java.io.Console;
import java.io.IOException;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;
import java.util.function.Function;


@JBossLog
public class UserRepository {
    
    
    private DataSourceProvider  dataSourceProvider;
    private QueryConfigurations queryConfigurations;
    
    public UserRepository(DataSourceProvider dataSourceProvider, QueryConfigurations queryConfigurations) {
        this.dataSourceProvider  = dataSourceProvider;
        this.queryConfigurations = queryConfigurations;
    }
    
    
    private <T> T doQuery(String query, Pageable pageable, Function<ResultSet, T> resultTransformer, Object... params) {
        Optional<DataSource> dataSourceOpt = dataSourceProvider.getDataSource();
        if (dataSourceOpt.isPresent()) {
            DataSource dataSource = dataSourceOpt.get();
            try (Connection c = dataSource.getConnection()) {
                if (pageable != null) {
                    query = PagingUtil.formatScriptWithPageable(query, pageable, queryConfigurations.getRDBMS());
                }
                log.infov("Query: {0} params: {1} ", query, Arrays.toString(params));
                try (PreparedStatement statement = c.prepareStatement(query)) {
                    if (params != null) {
                        for (int i = 1; i <= params.length; i++) {
                            statement.setObject(i, params[i - 1]);
                        }
                    }
                    try (ResultSet rs = statement.executeQuery()) {
                        return resultTransformer.apply(rs);
                    }
                }
            } catch (SQLException e) {
                log.error(e.getMessage(), e);
            }
            return null;
        }
        return null;
    }
    
    private List<Map<String, String>> readMap(ResultSet rs) {
        try {
            List<Map<String, String>> data         = new ArrayList<>();
            Set<String>               columnsFound = new HashSet<>();
            for (int i = 1; i <= rs.getMetaData().getColumnCount(); i++) {
                String columnLabel = rs.getMetaData().getColumnLabel(i);
                columnsFound.add(columnLabel);
            }
            while (rs.next()) {
                Map<String, String> result = new HashMap<>();
                for (String col : columnsFound) {
                    result.put(col, rs.getString(col));
                }
                data.add(result);
            }
            return data;
        } catch (Exception e) {
            throw new DBUserStorageException(e.getMessage(), e);
        }
    }
    
    
    private Integer readInt(ResultSet rs) {
        try {
            return rs.next() ? rs.getInt(1) : null;
        } catch (Exception e) {
            throw new DBUserStorageException(e.getMessage(), e);
        }
    }
    
    private Boolean readBoolean(ResultSet rs) {
        try {
            return rs.next() ? rs.getBoolean(1) : null;
        } catch (Exception e) {
            throw new DBUserStorageException(e.getMessage(), e);
        }
    }
    
    private String readString(ResultSet rs) {
        try {
            return rs.next() ? rs.getString(1) : null;
        } catch (Exception e) {
            throw new DBUserStorageException(e.getMessage(), e);
        }
    }
    
    public List<Map<String, String>> getAllUsers() {
        return doQuery(queryConfigurations.getListAll(), null, this::readMap);
    }
    
    public int getUsersCount(String search) {
        if (search == null || search.isEmpty()) {
            return Optional.ofNullable(doQuery(queryConfigurations.getCount(), null, this::readInt)).orElse(0);
        } else {
            String query = String.format("select count(*) from (%s) count", queryConfigurations.getFindBySearchTerm());
            return Optional.ofNullable(doQuery(query, null, this::readInt, search)).orElse(0);
        }
    }
    
    
    public Map<String, String> findUserById(String id) {
        return Optional.ofNullable(doQuery(queryConfigurations.getFindById(), null, this::readMap, id))
                       .orElse(Collections.emptyList())
                       .stream().findFirst().orElse(null);
    }
    
    public Optional<Map<String, String>> findUserByUsername(String username) {
        return Optional.ofNullable(doQuery(queryConfigurations.getFindByUsername(), null, this::readMap, username))
                       .orElse(Collections.emptyList())
                       .stream().findFirst();
    }
    
    public List<Map<String, String>> findUsers(String search, PagingUtil.Pageable pageable) {
        if (search == null || search.isEmpty()) {
            return doQuery(queryConfigurations.getListAll(), pageable, this::readMap);
        }
        return doQuery(queryConfigurations.getFindBySearchTerm(), pageable, this::readMap, search);
    }
    
    public boolean validateCredentials(String username, String password) {
        String hash = Optional.ofNullable(doQuery(queryConfigurations.getFindPasswordHash(), null, this::readString, username)).orElse("");

        // Decode the password hash from Base64, if needed
        if (queryConfigurations.isHashBase64().equals("true")) {
            hash = Hex.encodeHexString(Base64.getDecoder().decode(hash));
        }

        // Convert the string to bytes, confidering the unicode encoding of the password string
        byte[] pwdBytes;
        switch (queryConfigurations.getPasswordEncoding()) {
            case "UTF-8":
                pwdBytes = StringUtils.getBytesUtf8(password);
                break;
            case "UTF-16":
                pwdBytes = StringUtils.getBytesUtf16(password);
                break;
            case "UTF-16BE":
                pwdBytes = StringUtils.getBytesUtf16Be(password);
                break;
            case "UTF-16LE":
                pwdBytes = StringUtils.getBytesUtf16Le(password);
                break;
            default:
                pwdBytes = StringUtils.getBytesUtf8(password);
        }

        // Look to see if the password should be salted
        String saltLocation = queryConfigurations.getSaltLocation();
        if (!saltLocation.equals("None")) {
            String salt = doQuery(queryConfigurations.getFindPasswordSalt(), null, this::readString, username);
            log.infov("Decoding salt from: {0}", salt);
            byte[] decodedSalt = Base64.getDecoder().decode(salt);
            log.infov("Decoded salt to: {0}", Hex.encodeHexString(decodedSalt));

            // Add the salt
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
            try {
                if (saltLocation.equals("Prepend")) {
                    log.infov("Prepending salt: {0}", Hex.encodeHexString(decodedSalt));
                    outputStream.write(decodedSalt);
                    outputStream.write(pwdBytes);
                } else {
                    log.infov("Appending salt {0}", Hex.encodeHexString(decodedSalt));
                    outputStream.write(pwdBytes);
                    outputStream.write(decodedSalt);
                }
                pwdBytes = outputStream.toByteArray( );
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        if (queryConfigurations.isBlowfish()) {
            return !hash.isEmpty() && BCrypt.checkpw(new String(pwdBytes), hash);
        } else {
            String hashFunction = queryConfigurations.getHashFunction();

            if(hashFunction.equals("PBKDF2-SHA256")){
                String[] components = hash.split("\\$");
                return new PBKDF2SHA256HashingUtil(new String((pwdBytes)), components[2], Integer.valueOf(components[1])).validatePassword(components[3]);
            }

            log.infov("Generating hash using {0} of {1}", hashFunction, Hex.encodeHexString(pwdBytes));

            MessageDigest digest   = DigestUtils.getDigest(hashFunction);

            log.infov("Comparing {0} to expected {1}", Hex.encodeHexString(digest.digest(pwdBytes)), hash);

            return Objects.equals(Hex.encodeHexString(digest.digest(pwdBytes)), hash);
        }
    }
    
    public boolean updateCredentials(String username, String password) {
        throw new NotImplementedException("Password update not supported");
    }
    
    public boolean removeUser() {
        return queryConfigurations.getAllowKeycloakDelete();
    }
}
