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

import core.pefile.*;
import core.signature.CommunPatern;
import core.signature.Composant;
import core.signature.ComposantType;

/**
 * Implementation du patern de la version vanilla
 * 
 * @author r0da
 */
public class VanillaVersion extends CommunPatern {

    public VanillaVersion() {
        super();

        // Il y a bien evidement des methods moins longues a mettre en place pour representer un patern
        // Mais c'est pour utiliser la programmation object que j'ai fais ca :)
        // C'est en accord avec le sujet
        
        // Header du conteneur jar2exe
        paternCollection.add(new Composant(0xEF, ComposantType.STATIC));
        paternCollection.add(new Composant(0xBB, ComposantType.STATIC));
        paternCollection.add(new Composant(0xBF, ComposantType.STATIC));
        paternCollection.add(new Composant(0x73, ComposantType.STATIC));
        paternCollection.add(new Composant(0x65, ComposantType.STATIC));
        paternCollection.add(new Composant(0x72, ComposantType.STATIC));
        paternCollection.add(new Composant(0x69, ComposantType.STATIC));
        paternCollection.add(new Composant(0x61, ComposantType.STATIC));
        paternCollection.add(new Composant(0x6C, ComposantType.STATIC));
    }

    // Nom de la variante
    public String getName() {
        return "not protected variant";
    }

    @Override
    public boolean isFound(PE executable) {

        if(executable.resource.existsResourceType("RCDATA"))
            return false;
        
        SectionEntry resourceSection = executable.sections.getSectionByName(Symbols.RESOURCE_SECTION_NAME);
        
        int EOF = resourceSection.pointerToRawData + resourceSection.sizeOfRawData; 
        
        return super.isPaternFound(executable, EOF);
    }
    
    // On applique les effets du patern apres l'avoir trouvé        
    @Override
    public void applyAspects(PE executable){ 
        
        executable.security = Security.Null;
    }
}
