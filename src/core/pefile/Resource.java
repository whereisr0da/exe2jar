/**
 * Exe2Jar - Copyright (c) 2018 - 2019 r0da [r0da@protonmail.ch]
 *
 * This work is licensed under the Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 International License.
 * To view a copy of this license, visit http://creativecommons.org/licenses/by-nc-nd/4.0/ or send a letter to
 * Creative Commons, PO Box 1866, Mountain View, CA 94042, USA.
 *
 * By using Exe2Jar, you agree to the above license and its terms.
 *
 *      Attribution - You must give appropriate credit, provide a link to the license and indicate if changes were
 *                    made. You must do so in any reasonable manner, but not in any way that suggests the licensor
 *                    endorses you or your use.
 *
 *   Non-Commercial - You may not use the material (Exe2Jar) for commercial purposes.
 *
 *   No-Derivatives - If you remix, transform, or build upon the material (Exe2Jar), you may not distribute the
 *                    modified material. You are, however, allowed to submit the modified works back to the original
 *                    Exe2Jar project in attempt to have it added to the original project.
 *
 * You may not apply legal terms or technological measures that legally restrict others
 * from doing anything the license permits.
 *
 * No warranties are given.
 */

package core.pefile;

import core.stream.Reader;
import java.util.ArrayList;

public class Resource {
    
    // Reader du fichier
    private Reader reader;
    
    // Adresse des resources
    public int resourceOffset;
    
    // Nombre d'entrée resource
    public int numberOfEntries;
    
    // Adresse des entrées resource
    public int entryStartOffset;

    // List des entrées resources
    public ArrayList<ResourceEntry> entrys;
    
    // Section resource
    private SectionEntry resourceSection;
    
    /**
     * Contructeur du collecteur de resource
     * 
     * @param Reader reader : reader du fichier
     * @param SectionEntry resourceSection : section resource
     */
    public Resource(Reader reader, SectionEntry resourceSection){
        
        this.reader = reader;
        
        this.resourceSection = resourceSection;
        
        this.resourceOffset = resourceSection.pointerToRawData;
        
        this.numberOfEntries = reader.readInt16(resourceOffset + 0xE);
        
        this.entryStartOffset = resourceOffset + 0x10;
        
        this.entrys = new ArrayList<ResourceEntry>();
        
        int firstEntryOffset = 0;
        
        int entryCountTmp = 0;
        
        // NOTE : ce code n'est pas totalement exact car je ne stock que la premiere 
        //        entrée de donnée de la definition de resource. Je n'en n'ai pas l'utilité
        
        for (int i = 0; i < this.numberOfEntries; i++) {
            
            // Adresse de l'entrée courante
            int currentEntry = this.entryStartOffset + (Symbols.RESOURCE_ENTRY_DIR_SIZE * i);
            
            int type = reader.readInt32(currentEntry);
            
            int dataEntryOffset = this.resourceOffset + reader.readInt16(this.entryStartOffset + (Symbols.RESOURCE_ENTRY_DIR_SIZE * i) + 4);

            // Je stoque l'adresse de la premiere entrée
            if(firstEntryOffset == 0)
                firstEntryOffset = dataEntryOffset;
            
            int entryCount = reader.readInt16(dataEntryOffset + 0xE);
            
            int dataHeaderOffset = firstEntryOffset + (0x10 * (entryCountTmp)) + 0x130;
            
            int dataOffset = reader.readInt32(dataHeaderOffset);
            
            int size = reader.readInt32(dataHeaderOffset + 0x4);
            
            // L'adresse de l'entrée data est calculée en fonction du nombre d'entrée de donnée
            // Voir : https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#the-rsrc-section
            entryCountTmp += entryCount;
            
            this.entrys.add(new ResourceEntry(type,dataEntryOffset,entryCount,dataOffset,size));
        }
    }
    
    /**
     * Renvoie le buffer de donnée d'une resource
     * 
     * @param String str : nom de la resource
     * @return le buffer de donnée de la resource
     */
    public byte[] getResourceDataByName(String str){
        
        ResourceEntry entry = getResource(str);
        
        int virtualDataOffset = entry.dataOffset;
        
        // On calcul l'adresse des données dans le fichier a partir de l'adresse memoire
        int dataFileOffset = virtualDataOffset - resourceSection.virtualAddress + resourceSection.pointerToRawData;
                
        return this.reader.readBytes(dataFileOffset, entry.size);
    }
    
    /**
     * Renvoie l'entrée resource a partir de son nom
     * 
     * @param String str : nom de la resource
     * @return l'entrée resource
     */
    public ResourceEntry getResource(String str){
        
        for (ResourceEntry res : entrys) {
            if(res.type == getResourceIdFromType(str))
                return res;
        }
        
        return null;
    }
    
    /**
     * Indique si un type de resource exist
     * 
     * @param String str : type de resource
     * @return vrai si il exist dans les resources et faux a l'inverse
     */
    public boolean existsResourceType(String str){
        
        return getResource(str) != null;
    }
    
    /**
     * Renvoie le nom d'un type de resource a partir de son id
     * Voir : https://docs.microsoft.com/en-us/windows/desktop/menurc/resource-types
     * 
     * NOTE : code incomplet
     * 
     * @param int id : l'id
     * @return le nom du type de resource
     */
    public static String getResourceTypeFromId(int id){
        
        String result = "";
        
        switch(id){
            case Symbols.RT_RCDATA:
                result = "RCDATA";
                break;
        }
        
        return result;
    }
    
    /**
     * Renvoie l'id d'un type de resource a partir de son nom
     * Voir : https://docs.microsoft.com/en-us/windows/desktop/menurc/resource-types
     * 
     * NOTE : code incomplet
     * 
     * @param String id : son nom
     * @return l'id du type de resource
     */
    public static int getResourceIdFromType(String id){
        
        int result = 0;
        
        switch(id){
            case "RCDATA":
                result = Symbols.RT_RCDATA;
                break;
        }
        
        return result;
    }
}
