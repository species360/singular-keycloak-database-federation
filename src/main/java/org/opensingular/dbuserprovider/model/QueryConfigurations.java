package org.opensingular.dbuserprovider.model;

import org.opensingular.dbuserprovider.persistence.RDBMS;

public class QueryConfigurations {

    private String count;
    private String listAll;
    private String findById;
    private String findByUsername;
    private String findBySearchTerm;
    private String findPasswordHash;
    private String passwordEncoding;
    private String hashIsBase64;
    private String findPasswordSalt;
    private String saltLocation;
    private String hashFunction;
    private RDBMS  RDBMS;
    private boolean allowKeycloakDelete;
    private boolean allowDatabaseToOverwriteKeycloak;

    public QueryConfigurations(String count, String listAll, String findById, String findByUsername, String findBySearchTerm, String findPasswordHash, String passwordEncoding, String hashIsBase64, String findPasswordSalt, String saltLocation, String hashFunction, RDBMS RDBMS, boolean allowKeycloakDelete, boolean allowDatabaseToOverwriteKeycloak) {
        this.count = count;
        this.listAll = listAll;
        this.findById = findById;
        this.findByUsername = findByUsername;
        this.findBySearchTerm = findBySearchTerm;
        this.findPasswordSalt = findPasswordSalt;
        this.saltLocation = saltLocation;
        this.findPasswordHash = findPasswordHash;
        this.passwordEncoding = passwordEncoding;
        this.hashIsBase64 = hashIsBase64;
        this.hashFunction = hashFunction;
        this.RDBMS = RDBMS;
        this.allowKeycloakDelete = allowKeycloakDelete;
        this.allowDatabaseToOverwriteKeycloak = allowDatabaseToOverwriteKeycloak;
    }

    public RDBMS getRDBMS() {
        return RDBMS;
    }

    public String getCount() {
        return count;
    }

    public String getListAll() {
        return listAll;
    }

    public String getFindById() {
        return findById;
    }

    public String getFindByUsername() {
        return findByUsername;
    }

    public String getFindBySearchTerm() {
        return findBySearchTerm;
    }

    public String getFindPasswordHash() {
        return findPasswordHash;
    }
    public String getPasswordEncoding() {
        return passwordEncoding;
    }
    public String isHashBase64() {
        return hashIsBase64;
    }

    public String getFindPasswordSalt() {
        return findPasswordSalt;
    }

    public String getSaltLocation() {
        return saltLocation;
    }

    public String getHashFunction() {
        return hashFunction;
    }

    public boolean isBlowfish() {
        return hashFunction.toLowerCase().contains("blowfish");
    }

    public boolean getAllowKeycloakDelete() {
        return allowKeycloakDelete;
    }

    public boolean getAllowDatabaseToOverwriteKeycloak() {
        return allowDatabaseToOverwriteKeycloak;
    }
}
