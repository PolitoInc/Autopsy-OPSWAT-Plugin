/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.politoinc.metadefenderautopsy;

import org.openide.util.lookup.ServiceProvider;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModule;
import org.sleuthkit.autopsy.ingest.FileIngestModule;
import org.sleuthkit.autopsy.ingest.IngestModuleFactory;
import org.sleuthkit.autopsy.ingest.IngestModuleGlobalSettingsPanel;
import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettings;
import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettingsPanel;

/**
 *
 * @author Ian Duffy
 */
@ServiceProvider(service = IngestModuleFactory.class)
public class MetaDefenderLookupFactory implements IngestModuleFactory {
    public static final String VERSION_NUMBER = "1.0";
    public static final String DISPLAY_NAME = "MetaDefender Lookup Utility";
    public static final String DESCRIPTION = "Opswat MetaDefender file lookup utility";
    
    @Override
    public String getModuleDisplayName() {
        return DISPLAY_NAME;
    }

    @Override
    public String getModuleDescription() {
        return DESCRIPTION;
    }

    @Override
    public String getModuleVersionNumber() {
        return VERSION_NUMBER;
    }

    @Override
    public boolean hasGlobalSettingsPanel() {
        return false;
    }

    @Override
    public IngestModuleGlobalSettingsPanel getGlobalSettingsPanel() {
        return new MetaDefenderGlobalSettingsPanel();
    }

    @Override
    public IngestModuleIngestJobSettings getDefaultIngestJobSettings() {
        return new MetaDefenderSettings();
    }

    @Override
    public boolean hasIngestJobSettingsPanel() {
        return true;
    }

    @Override
    public IngestModuleIngestJobSettingsPanel getIngestJobSettingsPanel(IngestModuleIngestJobSettings imijs) {
        return new MetaDefenderIngestJobSettingsPanel((MetaDefenderSettings)imijs);
    }

    @Override
    public boolean isDataSourceIngestModuleFactory() {
        return false;
    }

    @Override
    public DataSourceIngestModule createDataSourceIngestModule(IngestModuleIngestJobSettings imijs) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean isFileIngestModuleFactory() {
        return true;
    }

    @Override
    public FileIngestModule createFileIngestModule(IngestModuleIngestJobSettings imijs) {
        return new MetaDefenderLookup((MetaDefenderSettings)imijs);
    }
}
