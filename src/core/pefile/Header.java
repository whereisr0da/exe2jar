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
import java.util.Arrays;

/**
 * Class / Struct du header PE
 *
 * basé sur cette documentation :
 * https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format
 *
 * @author r0da
 */
public class Header {

    /**
     * Reader de la class
     */
    Reader reader;

    /**
     * Adresse du header PE
     */
    public int peHeaderOffset;

    /**
     * Adresse de l'ImageBase
     */
    public int peHeaderImageBase;

    /**
     * Adresse relative de l'entrypoint
     */
    public int peRelativeEntryPointOffset;

    /**
     * Type d'application windows
     */
    public int peSubSystem;

    /**
     * Type d'architecture de l'application
     */
    public int peArchitecture;

    /**
     * Type de l'executable
     */
    public boolean is32bit;

    /**
     * Constructeur de la class Header
     * 
     * Verifie la validité de l'executable
     */
    public Header(Reader reader) {

        this.reader = reader;

        try {

            // On verifie si le fichier contient bien un header DOS
            if (!isValidDosHeader()) {
                throw new NoDosHeaderException();
            }

            // On verifie si le fichier contient bien une address vers le header PE
            if (getPeHeaderOffset() == 0) {
                throw new BadDosHeaderException();
            }

            // On verifie si le fichier contient le header PE
            if (!isValidPeHeader()) {
                throw new NoPeHeaderException();
            }

            // On verifie que l'adresse relative du point d'entré de l'executable existe 
            if (getRelativeEntryPointOffset() == 0) {
                throw new BadPeHeaderException();
            }

            this.peArchitecture = getArchitecture();

            this.peHeaderOffset = getPeHeaderOffset();

            this.is32bit = is32bit();

            this.peRelativeEntryPointOffset = getRelativeEntryPointOffset();

            this.peHeaderImageBase = getImageBase();

            this.peSubSystem = getSubSystem();

        } 
        catch (BadPeHeaderException e) {
            System.out.println("Error : The PE Header is invalid\r\n");
            System.exit(1);
        }
        catch (NoPeHeaderException e) {
            System.out.println("Error : PE Header not found\r\n");
            System.exit(1);
        }
        catch (BadDosHeaderException e) {
            System.out.println("Error : The DOS Header is invalid\r\n");
            System.exit(1);
        }
        catch (NoDosHeaderException e) {
            System.out.println("Error : DOS Header not found\r\n");
            System.exit(1);
        }
    }
    
    /**
     * Constructeur de la class Header a partir d'un executable
     */
    public Header(PE executable) {

        this.reader = executable.reader;

        try {
            
            // On verifie si le fichier contient bien un header DOS
            if (!isValidDosHeader()) {
                throw new NoDosHeaderException();
            }

            // On verifie si le fichier contient bien une address vers le header PE
            if (getPeHeaderOffset() == 0) {
                throw new BadDosHeaderException();
            }

            // On verifie si le fichier contient le header PE
            if (!isValidPeHeader()) {
                throw new NoPeHeaderException();
            }

            // On verifie que l'adresse relative du point d'entré de l'executable existe 
            if (getRelativeEntryPointOffset() == 0) {
                throw new BadPeHeaderException();
            }

            this.peArchitecture = getArchitecture();

            this.peHeaderOffset = getPeHeaderOffset();

            this.is32bit = is32bit();

            this.peRelativeEntryPointOffset = getRelativeEntryPointOffset();

            this.peHeaderImageBase = getImageBase();

            this.peSubSystem = getSubSystem();

        } 
        catch (BadPeHeaderException e) {
            System.out.println("Error : The PE Header is invalid\r\n");
            System.exit(1);
        }
        catch (NoPeHeaderException e) {
            System.out.println("Error : PE Header not found\r\n");
            System.exit(1);
        }
        catch (BadDosHeaderException e) {
            System.out.println("Error : The DOS Header is invalid\r\n");
            System.exit(1);
        }
        catch (NoDosHeaderException e) {
            System.out.println("Error : DOS Header not found\r\n");
            System.exit(1);
        }
    }
    
    /**
     * Verifie si l'entete DOS est bien la
     *
     * NOTE : public pour les tests unitaires
     *
     * @return vrai si l'executable commence bien par le magic header "MZ"
     */
    public boolean isValidDosHeader() {
        return Arrays.equals(reader.readBytes(0, 2), Symbols.MSDOS_HEADER);
    }

    /**
     * Renvoie l'adresse de l'entete PE
     *
     * @return l'adresse de l'entete PE dans le fichier
     */
    private int getPeHeaderOffset() {
        return reader.readInt32(0x3c);
    }

    /**
     * Verifie si l'entete PE est bien la
     *
     * NOTE : public pour les tests unitaires
     *
     * @return vrai si l'executable commence bien par le magic header "PE"
     */
    public boolean isValidPeHeader() {
        return Arrays.equals(reader.readBytes(getPeHeaderOffset(), 2), Symbols.PE_HEADER);
    }

    /**
     * Renvoie l'adresse relative du point d'entré
     *
     * @return l'adresse relative du point d'entré dans le fichier
     */
    private int getRelativeEntryPointOffset() {
        return reader.readInt32(getPeHeaderOffset() + 0x28);
    }

    /**
     * Renvoie l'adresse de base en memoire
     *
     * @return l'adresse de base en memoire
     */
    private int getImageBase() {

        if (!this.is32bit) {
            return reader.readInt64(getPeHeaderOffset() + 0x28 + 0x4 * 2);
        }

        return reader.readInt32(getPeHeaderOffset() + 0x34);
    }

    /**
     * Indique si l'executable est 32bit ou 64bit
     *
     * @return vrai si il est 32bit et faux dans le cas contraire
     */
    private boolean is32bit() {
        return getArchitecture() == Symbols.ARCH_INTEL386;
    }

    /**
     * Renvoie le type d'executable windows
     *
     * Voir :
     * https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#windows-subsystem
     *
     * @return le type d'executable
     */
    private int getSubSystem() {
        return reader.readInt16(getPeHeaderOffset() + 0x5C);
    }

    /**
     * Renvoie le type d'architecture de l'executable
     *
     * Voir :
     * https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#machine-types
     *
     * @return l'id du type d'architecture
     */
    private int getArchitecture() {

        return reader.readInt16(getPeHeaderOffset() + 0x4);
    }
}
