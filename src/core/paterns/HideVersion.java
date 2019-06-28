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

package core.paterns;

import core.extractor.*;
import core.pefile.*;
import core.signature.CommunPatern;

/**
 * Implementation du patern de la version cacher
 * 
 * @author r0da
 */
public class HideVersion extends CommunPatern {

    public HideVersion() {

        super();
    }

    // Nom de la variante
    public String getName() {
        return "hide variant";
    }

    @Override
    public boolean isFound(PE executable) {

        if(!executable.resource.existsResourceType("RCDATA"))
            return false;
        
        byte[] header = Unpacker.decryptHide(executable.resource.getResourceDataByName("RCDATA"));
        
        return header[0] == 0x50 && header[1] == 0x4B;
    }
    
    // On applique les effets du patern apres l'avoir trouvé
    @Override
    public void applyAspects(PE executable){ 
        
        executable.security = Security.Hidden;
    }
}