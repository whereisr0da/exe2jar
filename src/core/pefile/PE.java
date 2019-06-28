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
import core.exceptions.*;
import core.signature.*;
import java.util.*;

/**
 * Class de l'executable
 *
 * @author r0da
 */
public class PE {

    /**
     * Reader de la class
     */
    public Reader reader;

    /**
     * Header de l'executable
     */
    public Header header;

    /**
     * Resources de l'executable
     */
    public Resource resource;

    /**
     * Sections de l'executable
     */
    public Section sections;

    /**
     * Securtitée de l'executable
     */
    public Security security;

    /**
     * Constructeur de la class PE Verifie la validité de l'executable
     */
    public PE(String filePath) {

        // init le reader
        this.reader = new Reader(filePath);

        // init le header et le verifie
        this.header = new Header(reader);

        // init la securité
        this.security = Security.Null;

        // init les sections
        this.sections = new Section(reader, header);

        // init les resources
        this.resource = new Resource(reader, this.sections.getSectionByName(Symbols.RESOURCE_SECTION_NAME));
        
        // Point 10
        // L'exception suivante determine si 
        // l'executable est valide
        
        try {

            if (!isValidEntryPointOffset()) {
                throw new NoCodeSectionException();
            }

        } 
        catch (NoCodeSectionException e) {
            System.out.println("Error : There is no code section");
            System.exit(1);
        }
    }

    /**
     * Renvoie le nom de l'executable
     *
     * @return le nom de l'executable
     */
    public String name() {
        return this.reader.fileName();
    }

    /**
     * Indique si l'executable est 32bit ou 64bit
     *
     * NOTE : Simple raccourci
     *
     * @return vrai si il est 32bit et faux dans le cas contraire
     */
    public boolean is32bit() {
        return this.header.is32bit;
    }

    /**
     * Compare les instructions asm a une position absolue donné avec un
     * Composant donné
     *
     * @param Composant comp : le composant avec le quelle on compare
     * @param int position : la position absolue
     * @return vrai si le Composant est egale au buffer a l'adresse donné et
     * faux a l'inverse
     */
    public boolean compareRawData(Composant comp, int position) {

        // Si on ne cherche pas a comparer, on revoie vrai
        if (comp.type == ComposantType.UNKNOW) {
            return true;
        }

        int data = this.reader.readByte(position);

        return data == comp.value;
    }

    /**
     * Verifie si l'offset de l'entrypoint est valide
     *
     * @return vrai si l'entrypoint est valide
     */
    public boolean isValidEntryPointOffset() {
        return getFileEntryPointOffset() != 0;
    }
    
    // Point 2
    // La méthode compareEntryPoint() peut etre utilisée de plusieurs façons, en comparant un buffer
    // ou un patern a l'entrypoint, ou au dela de l'entrypoint avec une distance donnée
    
    /**
     * Compare les instructions asm de l'entrypoint avec un buffer donné
     *
     * @param byte[] buffer : le buffer avec le quelle on compare
     * @return vrai si le buffer est egale a l'ep et faux a l'inverse
     */
    public boolean compareEntryPoint(byte[] buffer) {
        return Arrays.equals(this.reader.readBytes(getFileEntryPointOffset(), buffer.length), buffer);
    }

    /**
     * Compare les instructions asm de l'entrypoint avec un Composant donné a
     * une position
     *
     * @param Composant comp : le composant avec le quelle on compare
     * @param int position : la position a ajouter a partir de l'ep
     * @return vrai si le composant est egale a l'ep et faux a l'inverse
     */
    public boolean compareEntryPoint(Composant comp, int position) {

        // Si on ne cherche pas a comparer, on revoie vrai
        if (comp.type == ComposantType.UNKNOW) {
            return true;
        }

        int instruction = this.reader.readByte(getFileEntryPointOffset() + position);

        return instruction == comp.value;
    }

    /**
     * Compare les instructions asm de l'entrypoint avec un buffer donné a une
     * position
     *
     * @param byte[] buffer : le buffer avec le quelle on compare
     * @param int position : la position a ajouter a partir de l'ep
     * @return vrai si le buffer est egale a l'ep et faux a l'inverse
     */
    public boolean compareEntryPoint(byte[] buffer, int position) {
        return Arrays.equals(this.reader.readBytes(getFileEntryPointOffset() + position, buffer.length), buffer);
    }

    /**
     * Calcule l'adresse de l'entrypoint depuis l'adresse relative de l'entète
     *
     * NOTE : l'adresse de l'entrypoint dans le fichier = adresse relative de
     * l'entrypoint - adresse virtuelle de la section ou est le code (dans 90%
     * des cas ".text") + adresse de la section dans le fichier
     *
     * @return l'adresse du point d'entré dans le fichier
     */
    public int getFileEntryPointOffset() {

        SectionEntry codeSection = this.sections.getSectionByName(Symbols.CODE_SECTION_NAME);

        return this.header.peRelativeEntryPointOffset - codeSection.virtualAddress + codeSection.pointerToRawData;
    }
}
