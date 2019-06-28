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

public class Symbols {
    
    public static final byte[] MSDOS_HEADER = new byte[] { 0x4D, 0x5A };
    
    public static final byte[] PE_HEADER = new byte[] { 0x50, 0x45 };
    
    // Doc : https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#machine-types
    public static final int ARCH_AMD64 = 0x8664;
    public static final int ARCH_INTEL386 = 0x14C;
    
    public static final String CODE_SECTION_NAME = ".text";
    
    public static final String RESOURCE_SECTION_NAME = ".rsrc";
    
    public static final int SECTION_NAME_SIZE = 7;
    
    public static final int RESOURCE_ENTRY_DIR_SIZE = 8;
    
    public static final int SECTION_SIZE = 0x28;
    
    // Doc : https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#windows-subsystem
    public static final int SUBSYS_WINDOWS_GUI = 2;
    public static final int SUBSYS_CONSOLE = 3;
    
    // Doc : https://docs.microsoft.com/en-us/windows/desktop/menurc/resource-types
    public static final int RT_RCDATA = 0xA;
}
