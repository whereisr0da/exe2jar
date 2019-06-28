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

import core.paterns.*;
import core.extractor.LicenceInfo;
import core.pefile.*;
import core.signature.*;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.jar.Pack200.Unpacker;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

public class InfoTest {
    
    @Test
    public void mainTest() {
        
        ArrayList<CommunPatern> paternList = new ArrayList<>();
        ArrayList<CommunPatern> variantList = new ArrayList<>();
        
        paternList.add(new x32());
        paternList.add(new x64());
        
        variantList.add(new EncryptedVersion());
        variantList.add(new HideVersion());
        variantList.add(new VanillaVersion());
        
        CommunCheck jar2exePaterns = new CommunCheck(paternList, "Result : jar2exe ");
        CommunCheck jar2exeVariants = new CommunCheck(variantList, "Type : ");
        
        char separator = '\\';
        
        // Credit : https://www.mkyong.com/java/how-to-detect-os-in-java-systemgetpropertyosname/
        
        String OS = System.getProperty("os.name").toLowerCase();
        
        if (OS.indexOf("nix") >= 0 || OS.indexOf("nux") >= 0 || OS.indexOf("aix") > 0) {
            separator = '/';
	}

        String dir = "sample" + separator;

        ArrayList<PE> list = new ArrayList<PE>();

        list.add(new PE(dir + "console32.bin"));
        list.add(new PE(dir + "console64.bin"));
        list.add(new PE(dir + "consoleHide32.bin"));
        list.add(new PE(dir + "consoleHide64.bin"));
        list.add(new PE(dir + "consoleEncrypt32.bin"));
        list.add(new PE(dir + "consoleEncrypt64.bin"));
        list.add(new PE(dir + "gui32.bin"));
        list.add(new PE(dir + "gui64.bin"));
        list.add(new PE(dir + "guiHide32.bin"));
        list.add(new PE(dir + "guiHide64.bin"));
        list.add(new PE(dir + "guiEncrypt32.bin"));
        list.add(new PE(dir + "guiEncrypt64.bin"));

        for (PE file : list) {

            // On a bien trouvé une variante
            assertEquals(jar2exePaterns.invoke(file), true);

            // On a bien determiné son type
            assertEquals(jar2exeVariants.invoke(file), true);

            // On a bien obtenue son machine id
            mainClassTest(file);

            // On a bien obtenue son machine id
            if (file.header.peSubSystem != Symbols.SUBSYS_CONSOLE) {
                machineIdTest(file);
            }
        }

        // On test la bonne architecture
        assertEquals(getFromName(list, "console32.bin").is32bit(), true);
        assertEquals(getFromName(list, "consoleHide32.bin").is32bit(), true);
        assertEquals(getFromName(list, "consoleEncrypt32.bin").is32bit(), true);
        assertEquals(getFromName(list, "gui32.bin").is32bit(), true);
        assertEquals(getFromName(list, "guiEncrypt32.bin").is32bit(), true);
        assertEquals(getFromName(list, "guiHide32.bin").is32bit(), true);
        assertEquals(!getFromName(list, "console64.bin").is32bit(), true);
        assertEquals(!getFromName(list, "consoleHide64.bin").is32bit(), true);
        assertEquals(!getFromName(list, "consoleEncrypt64.bin").is32bit(), true);
        assertEquals(!getFromName(list, "gui64.bin").is32bit(), true);
        assertEquals(!getFromName(list, "guiEncrypt64.bin").is32bit(), true);
        assertEquals(!getFromName(list, "guiHide64.bin").is32bit(), true);

        // On determine le bon type
        assertEquals(getFromName(list, "console32.bin").security, Security.Null);
        assertEquals(getFromName(list, "console64.bin").security, Security.Null);
        assertEquals(getFromName(list, "gui32.bin").security, Security.Null);
        assertEquals(getFromName(list, "gui64.bin").security, Security.Null);

        assertEquals(getFromName(list, "consoleHide32.bin").security, Security.Hidden);
        assertEquals(getFromName(list, "consoleHide64.bin").security, Security.Hidden);
        assertEquals(getFromName(list, "guiHide32.bin").security, Security.Hidden);
        assertEquals(getFromName(list, "guiHide64.bin").security, Security.Hidden);

        assertEquals(getFromName(list, "guiEncrypt32.bin").security, Security.Encrypted);
        assertEquals(getFromName(list, "guiEncrypt64.bin").security, Security.Encrypted);
        assertEquals(getFromName(list, "consoleEncrypt32.bin").security, Security.Encrypted);
        assertEquals(getFromName(list, "consoleEncrypt64.bin").security, Security.Encrypted);
    }

    private PE getFromName(ArrayList<PE> list, String name) {
        for (PE file : list) {
            if (file.name().equals(name)) {
                return file;
            }
        }

        return null;
    }

    public void mainClassTest(PE executable) {
        LicenceInfo info = new LicenceInfo(executable);

        System.out.println("Testing Main Class of " + executable.name());

        String mainClass = info.getMainClass();

        assertEquals(mainClass, "testapp.TestApp");
    }

    public void machineIdTest(PE executable) {
        LicenceInfo info = new LicenceInfo(executable);

        System.out.println("Testing Machine ID of " + executable.name());

        String machineId = info.getMachineId();

        assertEquals(machineId, "DE518263-B17C");
    }
}
