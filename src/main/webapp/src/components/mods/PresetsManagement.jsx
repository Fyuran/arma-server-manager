import * as React from "react";
import {useEffect, useState} from "react";
import {deleteModPreset, getModPresets, updateModPreset} from "../../services/modPresetsService";
import Table from "@mui/material/Table";
import TableContainer from "@mui/material/TableContainer";
import Paper from "@mui/material/Paper";
import TableCell from "@mui/material/TableCell";
import TableRow from "@mui/material/TableRow";
import TableHead from "@mui/material/TableHead";
import TableBody from "@mui/material/TableBody";
import {Box, Modal, Toolbar} from "@mui/material";
import Typography from "@mui/material/Typography";
import IconButton from '@mui/material/IconButton';
import DeleteIcon from '@mui/icons-material/Delete';
import EditIcon from '@mui/icons-material/Edit';
import SERVER_NAMES from "../../util/serverNames";
import {toast} from "material-react-toastify";
import ListBuilder from "../../UI/ListBuilder/ListBuilder";
import {getMods} from "../../services/modsService";
import TableGhosts from "../../UI/TableSkeletons";

export default function PresetsManagement() {
    const [initialLoading, setInitialLoading] = useState(true);
    const [presets, setPresets] = useState([]);
    const [editedPreset, setEditedPreset] = useState();
    const [presetModalOpen, setPresetModalOpen] = useState(false);
    const [selectedMods, setSelectedMods] = useState([]);
    const [availableMods, setAvailableMods] = useState();

    useEffect(() => {
        async function fetchPresets() {
            const {data: presetsDto} = await getModPresets();
            setPresets(presetsDto.presets);
            setInitialLoading(false);
        }

        fetchPresets();
    }, []);

    async function handleDelete(id) {
        const deletedPreset = presets.find(preset => preset.id === id);
        setPresets(prevState => [...prevState].filter(preset => preset !== deletedPreset));

        try {
            await deleteModPreset(id);
            toast.success(`Preset '${deletedPreset.name}' successfully deleted`);
        } catch (e) {
            console.error(e);
            toast.error(e.response.data || "Could not delete preset");
            setPresets(prevState => [...prevState, deletedPreset]);
        }
    }

    function getSummarizedModsList(mods) {
        const CUTOFF_LENGTH = 55;
        const modNames = mods.map(mod => mod.shortName);
        modNames.sort((a, b) => a.localeCompare(b));
        let summarizedList = modNames[0];
        let i = 1;
        while (summarizedList.length < CUTOFF_LENGTH && i < modNames.length) {
            summarizedList += ", " + modNames[i++];
        }
        if (summarizedList.length >= CUTOFF_LENGTH) {
            summarizedList += " and " + (modNames.length - i) + " more...";
        }
        return summarizedList;
    }

    function getSortedPresets() {
        return presets.sort((a, b) => a.name.localeCompare(b.name));
    }

    async function handleOpenEdit(preset) {
        const {data: modsDto} = await getMods(preset.type);
        let availableMods = modsDto.workshopMods;
        availableMods = availableMods.filter(mod => !preset.mods.find(searchedMod => searchedMod.id === mod.id))

        setEditedPreset(preset);
        setSelectedMods(preset.mods);
        setAvailableMods(availableMods);
        setPresetModalOpen(true);
    }

    async function handlePresetModalClosed() {
        const request = {
            name: editedPreset.name,
            mods: selectedMods.map(mod => mod.id)
        }

        if (selectedMods.length === 0) {
            await handleDelete(editedPreset.id);
        } else {
            try {
                const {data: savedPreset} = await updateModPreset(editedPreset.id, request);
                setPresets(prevState => {
                    const newState = [...prevState];
                    const oldPreset = newState.find(preset => preset.id === savedPreset.id);
                    return [...newState.filter(preset => preset !== oldPreset), savedPreset];
                });
                toast.success(`Preset '${savedPreset.name}' successfully updated`);
            } catch (e) {
                console.error(e);
                toast.error(e.response.data || "Could not update preset");
            }
        }

        setEditedPreset(null);
        setSelectedMods([]);
        setAvailableMods([]);
        setPresetModalOpen(false);
    }

    function handleModSelect(option) {
        setAvailableMods((prevState) => {
            return prevState.filter(item => item !== option);
        });
        setSelectedMods((prevState) => {
            return [option, ...prevState].sort((a, b) => a.name.localeCompare(b.name));
        });
    }

    function handleModDeselect(option) {
        setSelectedMods((prevState) => {
            return prevState.filter(item => item !== option);
        });

        setAvailableMods((prevState) => {
            return [option, ...prevState].sort((a, b) => a.name.localeCompare(b.name));
        });
    }

    return (
            <>
                <Box sx={{width: '100%'}}>
                    <Paper sx={{width: '100%'}}>
                        <Toolbar sx={{pl: {sm: 2}, pr: {xs: 1, sm: 1}}}>
                            <Typography sx={{flex: '1 1 100%'}} variant="h6" id="tableTitle" component="div">
                                Presets
                            </Typography>
                        </Toolbar>
                        <TableContainer component={Paper}>
                            <Table sx={{minWidth: 650}} aria-label="simple table">
                                <TableHead>
                                    <TableRow>
                                        <TableCell>Name</TableCell>
                                        <TableCell>Type</TableCell>
                                        <TableCell>Mods</TableCell>
                                        <TableCell align="right">Mods count</TableCell>
                                        <TableCell></TableCell>
                                        <TableCell></TableCell>
                                    </TableRow>
                                </TableHead>
                                <TableBody>
                                    {getSortedPresets().map((preset) => (
                                            <TableRow
                                                    key={preset.id}
                                                    sx={{'&:last-child td, &:last-child th': {border: 0}}}
                                            >
                                                <TableCell component="th" scope="row">
                                                    {preset.name}
                                                </TableCell>
                                                <TableCell>
                                                    {SERVER_NAMES[preset.type]}
                                                </TableCell>
                                                <TableCell>
                                                    {getSummarizedModsList(preset.mods)}
                                                </TableCell>
                                                <TableCell align="right">
                                                    {preset.mods.length}
                                                </TableCell>
                                                <TableCell>
                                                    <IconButton aria-label="edit"
                                                                onClick={() => handleOpenEdit(preset)}>
                                                        <EditIcon color="primary"/>
                                                    </IconButton>
                                                </TableCell>
                                                <TableCell>
                                                    <IconButton aria-label="delete"
                                                                onClick={() => handleDelete(preset.id)}>
                                                        <DeleteIcon color="error"/>
                                                    </IconButton>
                                                </TableCell>
                                            </TableRow>
                                    ))}
                                </TableBody>
                            </Table>
                            <TableGhosts display={initialLoading} count={10}/>
                        </TableContainer>
                    </Paper>
                </Box>
                <Modal open={presetModalOpen} onClose={handlePresetModalClosed}>
                    <Box>
                        <ListBuilder selectedOptions={selectedMods} availableOptions={availableMods}
                                     onSelect={handleModSelect} onDeselect={handleModDeselect}
                                     itemsLabel="mods" showFilter
                        />
                    </Box>
                </Modal>
            </>
    )
}