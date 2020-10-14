/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.politoinc.metadefenderautopsy;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;
import javax.net.ssl.HttpsURLConnection;
import org.sleuthkit.autopsy.casemodule.Case;
import org.openide.util.Exceptions;
import org.sleuthkit.autopsy.casemodule.services.TagsManager;
import org.sleuthkit.autopsy.ingest.FileIngestModule;
import org.sleuthkit.autopsy.ingest.IngestJobContext;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.HashUtility;
import org.sleuthkit.datamodel.TagName;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.Blackboard;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardAttribute;

/**
 *
 * @author Ian Duffy
 */
public class MetaDefenderLookup implements FileIngestModule {
    private static final String URIformat = "/v4/hash/%s";
    
    private TagsManager tagsManager;
    private String tagNameString = "MetaDefender";
    private TagName moduleTag;
    private MetaDefenderSettings settings;
    Blackboard blackboard;
    
    public MetaDefenderLookup(MetaDefenderSettings settings) {
        this.settings = settings;
    }
    
    @Override
    public ProcessResult process(AbstractFile file) {
        if (file.isFile() && file.canRead()) {
            if (file.getMd5Hash() == null) {
                try {
                    HashUtility.calculateMd5(file);
                } catch (IOException ex) {
                    return ProcessResult.ERROR;
                }
            }
            try {
                String formattedURI = String.format(URIformat, file.getMd5Hash());
                String fullServerURL = "https://" + settings.getSERVER() + formattedURI;
                
                // Set up the connection
                URL theURL = new URL(fullServerURL);
                HttpURLConnection connection;
                if (settings.getUseSSL()) {
                    connection = (HttpsURLConnection)theURL.openConnection();
                } else {
                    connection = (HttpURLConnection)theURL.openConnection();
                }
                
                // Add the authorization header with the authorization information
                String APIKey = settings.getAPIKey();
                connection.addRequestProperty("apikey", APIKey);
                connection.addRequestProperty("Accept", "application/json");
                
                int ret = connection.getResponseCode();
                if (ret == 200) {
                    // Get the input and output streams
                    InputStream is = connection.getInputStream();
                    BufferedReader streamReader = new BufferedReader(new InputStreamReader(is));
                    StringBuilder responseStringBuilder = new StringBuilder();
                
                    String inputStr;
                    while ((inputStr = streamReader.readLine()) != null) {
                        responseStringBuilder.append(inputStr);
                    }
                    
                    String responseString = responseStringBuilder.toString();
                    JsonParser theParser = new JsonParser();
                    JsonElement response = theParser.parse(responseString);
                    JsonObject jobject = response.getAsJsonObject();
                    
                    JsonObject scanResults = jobject.getAsJsonObject("scan_results");
                    
                    if (scanResults != null) {
                        JsonElement totalDetectedAVs = scanResults.get("total_detected_avs");
                        JsonElement totalAVs = scanResults.get("total_avs");
                        JsonElement scanResultA = scanResults.get("scan_all_result_a");
                        JsonElement scanResultI = scanResults.get("scan_all_result_i");
                        
                        int iTotalDetectedAVs = -1;
                        int iTotalAVs = -1;
                        String sScanResult = null;
                        int iScanResult = -1;
                        
                        if (totalDetectedAVs != null) {
                            iTotalDetectedAVs = totalDetectedAVs.getAsInt();
                        }
                        
                        if (totalAVs != null) {
                            iTotalAVs = totalAVs.getAsInt();
                        }
                        
                        if (scanResultA != null) {
                            sScanResult = scanResultA.getAsString();
                        }
                        
                        if (scanResultI != null) {
                            iScanResult = scanResultI.getAsInt();
                        }
                        
                        if (iScanResult == 1 || (sScanResult != null && sScanResult.equals("Infected"))) {
                            StringBuilder tagStringBuilder = new StringBuilder("MetaDefender Results: ");
                        
                            if (sScanResult != null) {
                                tagStringBuilder.append(sScanResult);
                            }
                            
                            JsonPrimitive threatName = jobject.getAsJsonPrimitive("threat_name");
                            if (threatName != null) {
                                tagStringBuilder.append(" ");
                                tagStringBuilder.append(threatName.getAsString());
                            }

                            if (iTotalDetectedAVs > 0 && iTotalAVs > 0) {
                                tagStringBuilder.append(" ");
                                tagStringBuilder.append("(");
                                tagStringBuilder.append(iTotalDetectedAVs);
                                tagStringBuilder.append("/");
                                tagStringBuilder.append(iTotalAVs);
                                tagStringBuilder.append(")");
                            }
                            
                            //tagsManager.addContentTag(file, moduleTag, tagStringBuilder.toString());
                            BlackboardArtifact interestingFileArtifact = 
                                    file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT);
                            
                            BlackboardAttribute nameAttribute = 
                                    new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME,
                                            "MetaDefender Plugin", 
                                            "Malware");
                            
                            BlackboardAttribute detailsAttribute =
                                    new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_COMMENT, 
                                            "MetaDefender Plugin", 
                                            tagStringBuilder.toString());
                                  
                            interestingFileArtifact.addAttribute(nameAttribute);
                            interestingFileArtifact.addAttribute(detailsAttribute);
                            
                            blackboard.postArtifact(interestingFileArtifact, "MetaDefenderPlugin");
                            //IngestServices ingestServices = IngestServices.getInstance();
                            //ingestServices.fireModuleDataEvent(moduleDataEvent);
                        }
                    }
                }
            } catch (Exception e) {
                return ProcessResult.ERROR;
            } finally {
                if (settings.getRateLimitQueriesPerMinute() != 0) {
                    try {
                        Thread.sleep((60 * 1000) / settings.getRateLimitQueriesPerMinute());
                    } catch (Exception e) {}
                }
            }
        }
        return ProcessResult.OK;
    }
    
    @Override
    public void shutDown() {
    }

    @Override
    public void startUp(IngestJobContext ijc) throws IngestModuleException {
        if (settings.getAPIKey().equals(""))
            throw new IngestModuleException("Invalid MetaDefender Cloud API key.");
            
        tagsManager = Case.getCurrentCase().getServices().getTagsManager();
        blackboard = Case.getCurrentCase().getServices().getArtifactsBlackboard();
        try {
            moduleTag = tagsManager.addTagName(tagNameString, "Executable Files", TagName.HTML_COLOR.YELLOW);
        } catch (TagsManager.TagNameAlreadyExistsException e) {
            try {
                List<TagName> tagNames = tagsManager.getAllTagNames();
                for (int i=0; i<tagNames.size(); i++) {
                    TagName tagName = (TagName)tagNames.get(i);
                    if (tagName.getDisplayName().equals(tagNameString)) {
                        moduleTag = tagName;
                    }
                }
            } catch (TskCoreException ex) {
                Exceptions.printStackTrace(ex);
            }
        } catch (TskCoreException ex) {
            Exceptions.printStackTrace(ex);
        }
    }
}
