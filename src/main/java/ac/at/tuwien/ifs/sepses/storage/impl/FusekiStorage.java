package ac.at.tuwien.ifs.sepses.storage.impl;

import ac.at.tuwien.ifs.sepses.storage.Storage;
import ac.at.tuwien.ifs.sepses.storage.tool.StorageHelper;
import com.sun.javafx.PlatformUtil;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;

public enum FusekiStorage implements Storage {

    INSTANCE();

    private static final Logger log = LoggerFactory.getLogger(FusekiStorage.class);

    public static FusekiStorage getInstance() {
        return INSTANCE;
    }

    @Override
    public void storeData(String filename, String endpoint, String namegraph, Boolean isUseAuth, String user,
            String pass) {
        if (isUseAuth) {
            log.error("not handled yet");
            return;
        }

        long start = System.currentTimeMillis() / 1000;

        try {
            log.info("storing " + filename + " started");
            if (PlatformUtil.isWindows())
                filename = filename.replaceAll("/", "\\");
            String command = "s-post " + endpoint + " " + namegraph + " " + filename;
            Process process = Runtime.getRuntime().exec(command);
            InputStream is = process.getInputStream();
            IOUtils.copy(is, System.out);
            log.info("Data appended successfully");
        } catch (IOException e) {
            log.error(e.getMessage(), e);
        }

        long end = System.currentTimeMillis() / 1000;
        log.info("Writing process for '" + filename + "' took " + (end - start) + " seconds");
    }

    @Override public void replaceData(String file, String endpoint, String namegraph, Boolean isUseAuth, String user,
            String pass) {

        long start = System.currentTimeMillis() / 1000;

        if (isUseAuth) {
            log.error("Auth is not handled yet");
            return;
        }

        try {
            log.info("storing " + file + " started");
            if (PlatformUtil.isWindows())
                file = file.replaceAll("/", "\\");
            String command = "s-put " + endpoint + " " + namegraph + " " + file;
            Process process = Runtime.getRuntime().exec(command);
            InputStream is = process.getInputStream();
            IOUtils.copy(is, System.out);
            log.info("Data replaced successfully");
        } catch (IOException e) {
            log.error(e.getMessage(), e);
        }

        long end = System.currentTimeMillis() / 1000;
        log.info("Writing process for '" + file + "' took " + (end - start) + " seconds");

    }

    @Override public void executeUpdate(String endpoint, String query, Boolean isUseAuth, String user, String pass) {
        endpoint = endpoint + "/update";
        StorageHelper.executeUpdate(endpoint, query, isUseAuth, user, pass);
    }
}
