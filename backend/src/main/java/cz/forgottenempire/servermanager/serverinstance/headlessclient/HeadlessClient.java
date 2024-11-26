package cz.forgottenempire.servermanager.serverinstance.headlessclient;

import com.google.common.base.Joiner;
import cz.forgottenempire.servermanager.common.PathsFactory;
import cz.forgottenempire.servermanager.common.ServerType;
import cz.forgottenempire.servermanager.serverinstance.process.ServerProcessCreator;
import cz.forgottenempire.servermanager.serverinstance.entities.Arma3Server;
import lombok.extern.slf4j.Slf4j;
import org.apache.logging.log4j.util.Strings;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Configurable;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Stream;

@Slf4j
@Configurable
public class HeadlessClient {

    private final int id;
    private final Arma3Server server;
    private PathsFactory pathsFactory;
    private ServerProcessCreator serverProcessCreator;

    private Process process;

    public HeadlessClient(int id, Arma3Server server) {
        this.id = id;
        this.server = server;
    }

    public HeadlessClient start() {
        File executable = pathsFactory.getServerExecutableWithFallback(ServerType.ARMA3);
        File logFile = pathsFactory.getHeadlessClientLogFile(server.getId(), id);

        try {
            List<String> parameters = prepareParameters();
            log.info("Starting headless client with options: {}", Joiner.on(" ").join(parameters));
            process = serverProcessCreator.startProcessWithRedirectedOutput(executable, parameters, logFile);
        } catch (IOException e) {
            log.error("Failed to start headless client", e);
        }

        return this;
    }

    public void stop() {
        if (!isAlive()) {
            return;
        }
        process.destroy();
    }

    public boolean isAlive() {
        return process != null && process.isAlive();
    }

    private List<String> prepareParameters() {
        List<String> parameters = new ArrayList<>();
        parameters.add("-client");
        parameters.add("-connect=127.0.0.1:" + server.getPort());
        if (Strings.isNotBlank(server.getPassword())) {
            parameters.add("-password=" + server.getPassword());
        }
        parameters.add("-limitFPS=500 -hugePages -nologs");

        List<String> modParameters = Stream.of(
                        server.getClientModsAsParameters(),
                        server.getCreatorDlcsAsParameters(),
                        server.getAdditionalModsAsParameters()
                )
                .flatMap(Function.identity())
                .toList();

        parameters.addAll(modParameters);
        return parameters;
    }

    @Autowired
    void setPathsFactory(PathsFactory pathsFactory) {
        this.pathsFactory = pathsFactory;
    }

    @Autowired
    void setServerProcessCreator(ServerProcessCreator serverProcessCreator) {
        this.serverProcessCreator = serverProcessCreator;
    }
}
