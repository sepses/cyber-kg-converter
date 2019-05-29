package ac.at.tuwien.ifs.sepses.storage.impl;

import ac.at.tuwien.ifs.sepses.storage.Storage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public enum DummyStorage implements Storage {

    INSTANCE();

    private static final Logger log = LoggerFactory.getLogger(DummyStorage.class);

    public static DummyStorage getInstance() {
        return INSTANCE;
    }

    @Override public void storeData(String file, String endpoint, String namegraph, Boolean isUseAuth, String user,
            String pass) {
        log.info("Do nothing");

    }

    @Override public void replaceData(String file, String endpoint, String namegraph, Boolean isUseAuth, String user,
            String pass) {
        log.info("Do nothing");

    }

    @Override public void executeUpdate(String endpoint, String query, Boolean isUseAuth, String user, String pass) {
        log.info("Do nothing");
    }
}
