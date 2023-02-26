package cz.forgottenempire.servermanager.serverinstance.entities;

import cz.forgottenempire.servermanager.workshop.Arma3CDLC;
import cz.forgottenempire.servermanager.workshop.WorkshopMod;
import java.util.List;
import javax.persistence.Column;
import javax.persistence.ElementCollection;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.ManyToMany;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@Entity
public class Arma3Server extends Server {

    private boolean clientFilePatching;
    private boolean serverFilePatching;

    private boolean persistent;

    private boolean battlEye;
    private boolean vonEnabled;
    private boolean verifySignatures;

    @Column(columnDefinition = "LONGTEXT")
    private String additionalOptions;

    @ManyToMany
    private List<WorkshopMod> activeMods;

    @ElementCollection(targetClass = Arma3CDLC.class)
    @Enumerated(EnumType.STRING)
    private List<Arma3CDLC> activeDLCs;
}