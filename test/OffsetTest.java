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

import core.pefile.PE;
import core.pefile.Security;
import core.pefile.Symbols;

import org.junit.Test;
import static org.junit.Assert.*;

public class OffsetTest {
    
    @Test
    public void mainTest() {
    
        char separator = '\\';

        // Credit : https://www.mkyong.com/java/how-to-detect-os-in-java-systemgetpropertyosname/
        
        String OS = System.getProperty("os.name").toLowerCase();
        
        if (OS.indexOf("nix") >= 0 || OS.indexOf("nux") >= 0 || OS.indexOf("aix") > 0) {
            separator = '/';
	}
        
        String dir = "sample" + separator;
        
        PE executable = new PE(dir + "gui32.bin");

        assertEquals(executable.header.isValidDosHeader(), true);
        
        assertEquals(executable.header.isValidPeHeader(), true);
        
        assertEquals(executable.header.peHeaderOffset, 248);
        
        assertEquals(executable.header.peRelativeEntryPointOffset, 70704);
    
        assertEquals(executable.header.is32bit, true);
    
        assertEquals(executable.header.peSubSystem, 2);
    
        assertEquals(executable.header.peHeaderImageBase, 0x400000);
        
        assertEquals(executable.header.peArchitecture, Symbols.ARCH_INTEL386);
    
        assertEquals(executable.security, Security.Null);
    
        assertEquals(executable.resource.entryStartOffset, 0x2a010);
        
        assertEquals(executable.resource.numberOfEntries, 4);
        
        assertEquals(executable.resource.resourceOffset, 0x2a000);
    }
}
