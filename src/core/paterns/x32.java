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
import core.signature.*;

/**
 * Implementation du patern de la version 32 bit
 *
 * @author r0da
 */
public class x32 extends CommunPatern {

    public x32() {
        
        super();

        // Il y a bien evidement des methods moins longues a mettre en place pour representer un patern
        // Mais c'est pour utiliser la programmation object que j'ai fais ca :)
        // C'est en accord avec le sujet
        
        // Vouci le patern de l'entrypoint sous x86
        paternCollection.add(new Composant(0x55, ComposantType.STATIC));
        paternCollection.add(new Composant(0x8B, ComposantType.STATIC));
        paternCollection.add(new Composant(0xEC, ComposantType.STATIC));
        paternCollection.add(new Composant(0x6a, ComposantType.STATIC));
        paternCollection.add(new Composant(0x00, ComposantType.UNKNOW));    // ..
        paternCollection.add(new Composant(0x68, ComposantType.STATIC));
        paternCollection.add(new Composant(0x00, ComposantType.UNKNOW));    // ..
        paternCollection.add(new Composant(0x00, ComposantType.UNKNOW));    // ..
        paternCollection.add(new Composant(0x00, ComposantType.UNKNOW));    // ..
        paternCollection.add(new Composant(0x00, ComposantType.UNKNOW));    // ..
        paternCollection.add(new Composant(0x68, ComposantType.STATIC));
        paternCollection.add(new Composant(0x00, ComposantType.UNKNOW));    // ..
        paternCollection.add(new Composant(0x00, ComposantType.UNKNOW));    // ..
        paternCollection.add(new Composant(0x00, ComposantType.UNKNOW));    // ..
        paternCollection.add(new Composant(0x00, ComposantType.UNKNOW));    // ..
        paternCollection.add(new Composant(0x64, ComposantType.STATIC));
        paternCollection.add(new Composant(0xa1, ComposantType.STATIC));
        paternCollection.add(new Composant(0x00, ComposantType.UNKNOW));    // ..
        paternCollection.add(new Composant(0x00, ComposantType.UNKNOW));    // ..
        paternCollection.add(new Composant(0x00, ComposantType.UNKNOW));    // ..
        paternCollection.add(new Composant(0x00, ComposantType.UNKNOW));    // ..
        paternCollection.add(new Composant(0x50, ComposantType.STATIC));
        paternCollection.add(new Composant(0x64, ComposantType.STATIC));
        paternCollection.add(new Composant(0x89, ComposantType.STATIC));
        paternCollection.add(new Composant(0x25, ComposantType.STATIC));
        paternCollection.add(new Composant(0x00, ComposantType.UNKNOW));    // ..
        paternCollection.add(new Composant(0x00, ComposantType.UNKNOW));    // ..
        paternCollection.add(new Composant(0x00, ComposantType.UNKNOW));    // ..
        paternCollection.add(new Composant(0x00, ComposantType.UNKNOW));    // ..
        paternCollection.add(new Composant(0x83, ComposantType.STATIC));
        paternCollection.add(new Composant(0xec, ComposantType.STATIC));
        paternCollection.add(new Composant(0x00, ComposantType.UNKNOW));    // ..
        paternCollection.add(new Composant(0x53, ComposantType.STATIC));
        paternCollection.add(new Composant(0x56, ComposantType.STATIC));
        paternCollection.add(new Composant(0x57, ComposantType.STATIC));
        paternCollection.add(new Composant(0x89, ComposantType.STATIC));
        paternCollection.add(new Composant(0x65, ComposantType.STATIC));
        paternCollection.add(new Composant(0x00, ComposantType.UNKNOW));    // ..
        paternCollection.add(new Composant(0xff, ComposantType.STATIC));
        paternCollection.add(new Composant(0x15, ComposantType.STATIC));
        paternCollection.add(new Composant(0x00, ComposantType.UNKNOW));    // ..
        paternCollection.add(new Composant(0x00, ComposantType.UNKNOW));    // ..
        paternCollection.add(new Composant(0x00, ComposantType.UNKNOW));    // ..
        paternCollection.add(new Composant(0x00, ComposantType.UNKNOW));    // ..
        paternCollection.add(new Composant(0x33, ComposantType.STATIC));
        paternCollection.add(new Composant(0xd2, ComposantType.STATIC));
        paternCollection.add(new Composant(0x8a, ComposantType.STATIC));
        paternCollection.add(new Composant(0xd4, ComposantType.STATIC));
        paternCollection.add(new Composant(0x89, ComposantType.STATIC));
        paternCollection.add(new Composant(0x15, ComposantType.STATIC));
        paternCollection.add(new Composant(0x00, ComposantType.UNKNOW));    // ..
        paternCollection.add(new Composant(0x00, ComposantType.UNKNOW));    // ..
        paternCollection.add(new Composant(0x00, ComposantType.UNKNOW));    // ..
        paternCollection.add(new Composant(0x00, ComposantType.UNKNOW));    // ..
        paternCollection.add(new Composant(0x8b, ComposantType.STATIC));
        paternCollection.add(new Composant(0xc8, ComposantType.STATIC));
        paternCollection.add(new Composant(0x81, ComposantType.STATIC));
        paternCollection.add(new Composant(0xe1, ComposantType.STATIC));
        paternCollection.add(new Composant(0x00, ComposantType.UNKNOW));    // ..
        paternCollection.add(new Composant(0x00, ComposantType.UNKNOW));    // ..
        paternCollection.add(new Composant(0x00, ComposantType.UNKNOW));    // ..
        paternCollection.add(new Composant(0x00, ComposantType.UNKNOW));    // ..
        paternCollection.add(new Composant(0x89, ComposantType.STATIC));
        paternCollection.add(new Composant(0x0d, ComposantType.STATIC));
    }

    // Nom de la version
    public String getName() {
        return "version x32";
    }

    @Override
    public boolean isFound(PE executable) {
        
        return super.isPaternFound(executable);
    }

    @Override
    public void applyAspects(PE executable) {
        // rien a faire
    }
}
