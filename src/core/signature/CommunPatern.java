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

package core.signature;

import core.pefile.PE;
import java.util.*;

/**
 * Classe qui definit un patern
 *
 * @author r0da
 */
public abstract class CommunPatern implements Patern {


    // Liste de patern
    public ArrayList<Composant> paternCollection;

    public CommunPatern() {
        paternCollection = new ArrayList<Composant>();
    }

    /**
     * Check si un patern est present a l'entrypoint
     *
     * NOTE : fonction generique, si on doit mettre des conditions
     * supplementaire autres que le patern, on les definira dans isFound()
     * 
     * @param PE executable : executable sur le quel on test les paterns
     * @return vrai si un patern est trouvé
     */
    public boolean isPaternFound(PE executable) {

        int offset = 0;

        for (Composant c : paternCollection) {

            if (!executable.compareEntryPoint(c, offset)) {
                return false;
            }
            
            offset++;
        }

        return true;
    }
    
    /**
     * Check si un patern est present a un offset
     *
     * NOTE : fonction generique
     * 
     * @param PE executable : executable sur le quel on test les paterns
     * @param int startOffset : l'offset du fichier
     * @return vrai si un patern est trouvé
     */
    public boolean isPaternFound(PE executable, int startOffset) {

        int offset = startOffset;

        for (Composant c : paternCollection) {

            if (!executable.compareRawData(c, offset)) {
                return false;
            }
            
            offset++;
        }

        return true;
    }
    
    /**
     * Applique les effets d'un patern apres l'avoir trouvé 
     *
     * @param PE executable : executable sur le quel on test les paterns
     */
    public abstract void applyAspects(PE executable);

    /**
     * Check si un patern est present
     *
     * @param PE executable : executable sur le quel on test les paterns
     */
    public abstract boolean isFound(PE executable);
}
