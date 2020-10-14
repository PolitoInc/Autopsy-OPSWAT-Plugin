/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.politoinc.metadefenderautopsy;

import java.util.Base64;
import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettings;

/**
 *
 * @author Ian Duffy
 */
public class MetaDefenderSettings implements IngestModuleIngestJobSettings {
    private long VERSION = 1;
    private String SERVER = "api.metadefender.com";
    private String PORT = "";
    private String APIKey = "";
    private Boolean UseSSL = true;
    private int RateLimitQueriesPerMinute = 10;


    public long getVERSION() {
        return VERSION;
    }

    public String getSERVER() {
        return SERVER;
    }

    public void setSERVER(String SERVER) {
        this.SERVER = SERVER;
    }

    public String getPORT() {
        return PORT;
    }

    public void setPORT(String PORT) {
        this.PORT = PORT;
    }
    
    @Override
    public long getVersionNumber() {
        return VERSION;
    }

    public String getAPIKey() {
        return APIKey;
    }

    public void setAPIKey(String APIKey) {
        this.APIKey = APIKey;
    }

    public Boolean getUseSSL() {
        return UseSSL;
    }

    public void setUseSSL(Boolean UseSSL) {
        this.UseSSL = UseSSL;
    }

    public int getRateLimitQueriesPerMinute() {
        return RateLimitQueriesPerMinute;
    }

    public void setRateLimitQueriesPerMinute(int RateLimitQueriesPerMinute) {
        this.RateLimitQueriesPerMinute = RateLimitQueriesPerMinute;
    }
}
