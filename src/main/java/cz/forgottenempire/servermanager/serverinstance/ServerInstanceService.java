package cz.forgottenempire.servermanager.serverinstance;

import cz.forgottenempire.servermanager.common.ServerType;
import cz.forgottenempire.servermanager.serverinstance.entities.Arma3Server;
import cz.forgottenempire.servermanager.serverinstance.entities.DayZServer;
import cz.forgottenempire.servermanager.serverinstance.entities.Server;
import cz.forgottenempire.servermanager.serverinstance.exceptions.ModifyingRunningServerException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import jakarta.validation.constraints.NotNull;
import java.util.List;
import java.util.Optional;

@Service
@Slf4j
class ServerInstanceService {

    private final ServerRepository serverRepository;
    private final ServerProcessService processService;

    @Autowired
    public ServerInstanceService(
            ServerRepository serverRepository,
            ServerProcessService processService
    ) {
        this.serverRepository = serverRepository;
        this.processService = processService;
    }

    public List<Server> getAllServers() {
        return serverRepository.findAll();
    }

    public Optional<Server> getServer(@NotNull Long id) {
        return serverRepository.findById(id);
    }

    public Server createServer(Server server) {
        setDifficultySettingsForArma3Server(server);
        setInstanceIdForDayZServer(server);
        server.getConfigs().forEach(ServerConfig::generate);
        return serverRepository.save(server);
    }

    public Server updateServer(Server server) {
        if (processService.isServerInstanceRunning(server)) {
            throw new ModifyingRunningServerException("Cannot modify running server '" + server.getName() + "'");
        }
        return createServer(server);
    }

    public void deleteServer(Server server) {
        if (processService.isServerInstanceRunning(server)) {
            throw new ModifyingRunningServerException("Cannot delete running server '" + server.getName() + "'");
        }
        serverRepository.delete(server);
    }

    private void setDifficultySettingsForArma3Server(Server server) {
        if (server.getType() == ServerType.ARMA3) {
            Arma3Server arma3Server = (Arma3Server) server;
            arma3Server.getDifficultySettings().setServer(arma3Server);
            serverRepository.save(arma3Server);
        }
    }

    private void setInstanceIdForDayZServer(Server server) {
        Long id = server.getId();
        if (id == null) {
            id = serverRepository.save(server).getId();
        }

        if (server.getType() == ServerType.DAYZ || server.getType() == ServerType.DAYZ_EXP) {
            ((DayZServer) server).setInstanceId(id);
        }
    }
}
