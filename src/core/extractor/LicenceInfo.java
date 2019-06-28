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

package core.extractor;

import core.exceptions.*;
import core.pefile.*;
import java.util.*;
import javax.xml.bind.DatatypeConverter;

/**
 * Classe des informations jar2exe
 *
 * @author r0da
 */
public class LicenceInfo {

    // Adresse de la fin de l'executable
    public int EOF;

    // Executable courant
    public PE executable;

    /**
     * Constructeur de la classe des informations jar2exe
     */
    public LicenceInfo(PE executable) {

        this.executable = executable;

        try {

            if (executable.sections.getSectionByName(Symbols.RESOURCE_SECTION_NAME) == null) {
                throw new NoResourceSectionException();
            }
            
        } catch (NoResourceSectionException e) {
            System.out.println("Error : No resource sections");
            System.exit(1);
        }

        SectionEntry resourceSection = executable.sections.getSectionByName(Symbols.RESOURCE_SECTION_NAME);

        this.EOF = resourceSection.pointerToRawData + resourceSection.sizeOfRawData;
    }

    /**
     * Renvoie l'adresse du debut des informations de jar2exe
     *
     * @return l'adresse du debut des informations dans le fichier
     */
    public int infoStartOffset() {

        int i = 0;

        while (executable.reader.readByte(this.EOF + i) != 0x0D) {
            i++;
        }

        return this.EOF + i + 2;
    }

    /**
     * Renvoie l'adresse du hash dans les infos jar2exe
     *
     * @return l'adresse du hash
     */
    public int hashOffset() {

        return infoStartOffset() + 0xA
                + getMainClass().length() + 0xB
                + minVersion().length() + 9
                + maxVersion().length() + 7;
    }

    /**
     * Renvoie le hash du fichier verifié par jar2exe
     *
     * @return le hash du fichier
     */
    public String getMD5Check() {

        return DatatypeConverter.printHexBinary(executable.reader.readBytes(hashOffset(), 0x10));
    }

    /**
     * Renvoie les versions supportées par le fichier jar
     *
     * @return les versions sous forme de string
     */
    public String getJreVersion() {
        return minVersion() + " to " + maxVersion();
    }

    /**
     * Renvoie la version minimum supportée par le fichier jar
     *
     * @return la version minimum supportée sous forme de string
     */
    public String minVersion() {

        String versionMin = "";
        int infoOffset = infoStartOffset() + 0xA + getMainClass().length() + 4;
        int i = 0;

        try {

            if (!executable.reader.readString(infoOffset, 6).equals("minjre")) {
                throw new FailToReadVersionException();
            }

        } catch (FailToReadVersionException e) {
            System.out.println("Error : Fail to get minjre version");
            return "ERROR";
        }

        while (executable.reader.readByte(infoOffset + 7 + i) != 0x0D) {
            versionMin += executable.reader.readString(infoOffset + 7 + i, 1);
            i++;
        }

        return versionMin;
    }

    /**
     * Renvoie la version maximum supportée par le fichier jar
     *
     * @return la version maximum supportée sous forme de string
     */
    public String maxVersion() {

        String versionMax = "";

        int infoOffset = infoStartOffset() + 0xA + getMainClass().length() + 4;

        int i = 0;

        try {

            if (!executable.reader.readString(infoOffset + 7 + minVersion().length() + 2, 6).equals("maxjre")) {
                throw new FailToReadVersionException();
            }

        } catch (FailToReadVersionException e) {
            System.out.println("Error : Fail to get maxjre version");
            return "ERROR";
        }

        while (executable.reader.readByte(infoOffset + 7 + minVersion().length() + 9 + i) != 0x0D) {
            versionMax += executable.reader.readString(infoOffset + 7 + minVersion().length() + 9 + i, 1);
            i++;
        }

        return versionMax;
    }

    /**
     * Renvoie la classe principale du fichier jar
     *
     * @return la classe principale du fichier jar sous forme de string
     */
    public String getMainClass() {

        try {

            if (!executable.reader.readString(infoStartOffset(), 9).equals("mainclass")) {
                throw new NoMainClassException();
            }

        } catch (NoMainClassException e) {
            System.out.println("Error : Fail to get main class name");
            return "ERROR";
        }

        int startNameOffset = infoStartOffset() + 0xA;

        String className = "";

        int i = 0;

        // j'ai pas encore determiner comment il connait la taille du nom de la classe
        while (executable.reader.readByte(startNameOffset + i) != 0x0D) {
            className += executable.reader.readString(startNameOffset + i, 1);
            i++;
        }

        return className;
    }

    /**
     * Renvoie la date de creation verifiée par jar2exe
     *
     * @return la date de creation sous forme de string
     */
    public String getCreationDate() {

        Calendar calendar = getCreationDateCalendar();

        int mYear = calendar.get(Calendar.YEAR);
        int mMonth = calendar.get(Calendar.MONTH);
        int mDay = calendar.get(Calendar.DAY_OF_MONTH) - 1; // EU
        int mHour = calendar.get(Calendar.HOUR);
        int mMinute = calendar.get(Calendar.MINUTE);

        return mDay + "/" + mMonth + "/" + mYear + "";
    }

    /**
     * Renvoie la date de creation verifiée par jar2exe
     *
     * @return la date de creation sous forme de Calendar
     */
    public Calendar getCreationDateCalendar() {

        int dateOffset = 0;

        // x32
        if (executable.is32bit() && executable.security == Security.Null) {
            dateOffset = executable.sections.getSectionByName(".data").pointerToRawData + 0x230;
        } else if (executable.is32bit() && executable.security == Security.Hidden) {
            dateOffset = executable.sections.getSectionByName(".data").pointerToRawData + 0x620;
        } else if (executable.is32bit() && executable.security == Security.Encrypted) {
            dateOffset = executable.sections.getSectionByName(".data").pointerToRawData + 0x644;
        } // x64
        // CONSOLE
        else if (!executable.is32bit() && executable.security == Security.Null
                && executable.header.peSubSystem == Symbols.SUBSYS_CONSOLE) {
            dateOffset = executable.sections.getSectionByName(".rdata").pointerToRawData + 0xfb0;
        } else if (!executable.is32bit() && executable.security == Security.Hidden
                && executable.header.peSubSystem == Symbols.SUBSYS_CONSOLE) {
            dateOffset = executable.sections.getSectionByName(".rdata").pointerToRawData + 0x15d0;
        } else if (!executable.is32bit() && executable.security == Security.Encrypted
                && executable.header.peSubSystem == Symbols.SUBSYS_CONSOLE) {
            dateOffset = executable.sections.getSectionByName(".rdata").pointerToRawData + 0x1610;
        } // GUI
        else if (!executable.is32bit() && executable.security == Security.Null
                && executable.header.peSubSystem != Symbols.SUBSYS_CONSOLE) {
            dateOffset = executable.sections.getSectionByName(".rdata").pointerToRawData + 0x11c8;
        } else if (!executable.is32bit() && executable.security == Security.Hidden
                && executable.header.peSubSystem != Symbols.SUBSYS_CONSOLE) {
            dateOffset = executable.sections.getSectionByName(".rdata").pointerToRawData + 0x17e8;
        } else if (!executable.is32bit() && executable.security == Security.Encrypted
                && executable.header.peSubSystem != Symbols.SUBSYS_CONSOLE) {
            dateOffset = executable.sections.getSectionByName(".rdata").pointerToRawData + 0x1828;
        }

        int time_t = executable.reader.readInt32(dateOffset);

        Calendar calendar = Calendar.getInstance();

        // time_t
        calendar.set(Calendar.YEAR, 1970);
        calendar.set(Calendar.MONTH, 1);
        calendar.set(Calendar.DAY_OF_MONTH, 1);

        calendar.setTimeZone(TimeZone.getTimeZone("Europe/Paris"));

        calendar.add(Calendar.SECOND, time_t);

        return calendar;
    }

    /**
     * Calcule la date d'expiration verifiée par jar2exe
     *
     * @return la date d'expiration sous forme de string
     */
    public String getExpirationDate() {

        Calendar calendar = getCreationDateCalendar();

        calendar.add(Calendar.DAY_OF_MONTH, 7);

        int mYear = calendar.get(Calendar.YEAR);
        int mMonth = calendar.get(Calendar.MONTH);
        int mDay = calendar.get(Calendar.DAY_OF_MONTH) - 1;
        int mHour = calendar.get(Calendar.HOUR);
        int mMinute = calendar.get(Calendar.MINUTE);

        return mDay + "/" + mMonth + "/" + mYear + "";
    }

    /**
     * Renvoie l'id machine verifié avec la license jar2exe
     *
     * @return l'id machin sous forme de string
     */
    public String getMachineId() {

        int machineIdOffset = 0;

        // x32 vanilla
        if (executable.is32bit()
                && executable.security == Security.Null
                && executable.header.peSubSystem != Symbols.SUBSYS_CONSOLE) {

            machineIdOffset = executable.sections.getSectionByName(".data").pointerToRawData + 0x24C;

        } // x32 hideClass
        else if (executable.is32bit()
                && executable.security == Security.Hidden
                && executable.header.peSubSystem != Symbols.SUBSYS_CONSOLE) {

            machineIdOffset = executable.sections.getSectionByName(".data").pointerToRawData + 0x63C;

        } // x32 encryptedClass
        else if (executable.is32bit()
                && executable.security == Security.Encrypted
                && executable.header.peSubSystem != Symbols.SUBSYS_CONSOLE) {

            machineIdOffset = executable.sections.getSectionByName(".data").pointerToRawData + 0x660;

        } // x64 vanilla
        else if (!executable.is32bit()
                && executable.security == Security.Null
                && executable.header.peSubSystem != Symbols.SUBSYS_CONSOLE) {

            machineIdOffset = executable.sections.getSectionByName(".rdata").pointerToRawData + 0x11E8;

        } // x64 hideClass
        else if (!executable.is32bit()
                && executable.security == Security.Hidden
                && executable.header.peSubSystem != Symbols.SUBSYS_CONSOLE) {

            machineIdOffset = executable.sections.getSectionByName(".rdata").pointerToRawData + 0x1808;

        } // x64 encryptedClass
        else if (!executable.is32bit()
                && executable.security == Security.Encrypted
                && executable.header.peSubSystem != Symbols.SUBSYS_CONSOLE) {

            machineIdOffset = executable.sections.getSectionByName(".rdata").pointerToRawData + 0x1848;

        } // console app
        else if (executable.header.peSubSystem == Symbols.SUBSYS_CONSOLE) {
            return "TODO";
        }

        return executable.reader.readString(machineIdOffset, 0xD);
    }
}
