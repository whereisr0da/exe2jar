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

import core.pefile.PE;
import core.pefile.Security;

/**
 * Classe qui unpack le fichier jar
 *
 * @author r0da
 */
public class Unpacker {
        
    private PE executable;
    
    public LicenceInfo licenceInfo;
    
    /**
     * Constructeur de la class unpacker
     */
    public Unpacker(PE executable, LicenceInfo licenceInfo){
        
        this.executable = executable;
        this.licenceInfo = licenceInfo;
    }
   
    /**
     * Indique si le fichier jar peut etre extrait
     *
     * NOTE : je ne fais pas d'exception car je veux utiliser la valeur de retour 
     * 
     * @return vrai si la variante est supporté par le tool
     */
    public boolean supported(){
        byte[] buffer = getJarFileFromResource();
        
        if(buffer == null)
            return false;
        
        return (buffer[0] == 0x50) && (buffer[1] == 0x4B);
    }
    
    /**
     * Renvoie un buffer qui correspond au fichier jar
     *
     * @return un tableau de byte qui correspond au fichier jar
     */
    public byte[] getJarFileFromResource(){
        
        if(executable.security == Security.Hidden){
            
            byte[] cryptedBuffer = executable.resource.getResourceDataByName("RCDATA");

            return decryptHide(cryptedBuffer);
        }
        else if(executable.security == Security.Null){
            
            int jarFileOffset = this.licenceInfo.hashOffset() + 0x10; // taille du hash
            
            int jarFileSize = (int)executable.reader.size() - jarFileOffset;
            
            return executable.reader.readBytes(jarFileOffset, jarFileSize);
        }
        
        return null;
    }
    
    /**
     * Dechiffre le buffer chiffré de la variante Hidden
     *
     * @param byte[] buffer : tableau de byte chiffré
     * @return un tableau de byte dechiffré
     */
    public static byte[] decryptHide(byte[] buffer){
        
        byte[] decrypted = new byte[buffer.length];
        
        /*
               
        pas ouf...
        
        al = buff[i]
        
        mov     dl, al  // dl = buff[i]
        sar     dl, 6   // dl >> 6
        and     dl, 3   // dl &= 3
        shl     al, 2   // al *= 4
        or      dl, al  // dl | al
        
        */
        
        for (int j = 0; j < buffer.length; j++) {
            
            decrypted[j] = (byte)(4 * buffer[j] | ((buffer[j] >> 6) & 3));
        }
        
        return decrypted;
    }
}
