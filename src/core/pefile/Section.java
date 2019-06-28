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

import core.exceptions.*;
import core.stream.Reader;
import java.util.*;

public class Section {

    // Reader du fichier
    private Reader reader;

    // Header du fichier
    private Header header;


    // List des entrées resources
    public ArrayList<SectionEntry> sections;

    /**
     * Contructeur du collecteur de Section
     * 
     * @param Reader reader : reader du fichier
     * @param Header header : header du fichier
     */
    public Section(Reader reader, Header header) {

        this.reader = reader;

        this.sections = new ArrayList<>();

        this.header = header;

        try {

            // On verifie que la sections existent
            if (getSectionCount() == 0 || getSectionHeaderOffset() == 0) {
                throw new NoSectionException();
            }

            initializeSections();

            // On verifie que la section resource existe
            if (getSectionByName(Symbols.RESOURCE_SECTION_NAME) == null) {
                throw new NoResourceException();
            }
        } 
        catch (NoResourceException e) {
            System.out.println("Error : There is no resource section\r\n        So this is not a jar2exe executable");
            System.exit(0);
        }
        catch (NoSectionException e) {
            System.out.println("Error : There is no section in the executable\r\n");
            System.exit(1);
        }
    }

    /**
     * Collecte toutes les Sections de l'executable
     */
    private void initializeSections() {

        for (int i = 0; i < getSectionCount(); i++) {

            int sectionDefinitionOffset = this.getSectionHeaderOffset() + (Symbols.SECTION_SIZE * i);

            // x64
            if (!this.header.is32bit) {
                sectionDefinitionOffset++;
            }

            sections.add(processSection(sectionDefinitionOffset));
        }
    }

    /**
     * Revoie l'adresse de l'entete des section dans le fichier
     *
     * @return l'adresse de l'entete des section dans le fichier
     */
    public int getSectionHeaderOffset() {

        // x64
        if (!this.header.is32bit) {
            return this.header.peHeaderOffset + 0x107;
        }

        return this.header.peHeaderOffset + 0xf8;
    }

    /**
     * Renvoie un objet SectionEntry a partir d'un offset ou une section est
     * definie dans l'executable
     *
     * @param int offset : la position dans le fichier
     * @return la Section correspondante
     */
    private SectionEntry processSection(int offset) {

        String name = this.reader.readString(offset, Symbols.SECTION_NAME_SIZE).replaceAll("\\x00", "");

        int pointerToRawData = this.reader.readInt32(offset + 0x14);

        int virtualAddress = this.reader.readInt32(offset + 0xC);

        int sizeOfData = this.reader.readInt32(offset + 0x10);

        return new SectionEntry(name, virtualAddress, sizeOfData, pointerToRawData);
    }

    /**
     * Revoie le nombre de section dans l'executable
     *
     * @return le nombre de section dans l'executable
     */
    public int getSectionCount() {
        return this.reader.readInt16(this.header.peHeaderOffset + 0x6);
    }

    /**
     * Revoie la section qui correspond au nom que l'on cherche
     *
     * @param String name : nom de la section
     * @return la section voulu
     */
    public SectionEntry getSectionByName(String name) {

        for (SectionEntry s : sections) {
            if (s.name.equals(name)) {
                return s;
            }
        }

        return null;
    }
}
