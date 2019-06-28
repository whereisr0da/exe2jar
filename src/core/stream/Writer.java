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

package core.stream;

import core.exceptions.*;
import java.io.*;

/**
 * Classe du Writer (controleur du stream)
 * 
 * NOTE : je ne fait pas de sous exception pour les IOExceptions
 * car ce serait stupide d'imbriquer deux try pour gerer une FailToWriteException
 * qui reviendrait au meme que la premiere 
 * 
 * @author r0da
 */
public class Writer {
    
    // Handle du fichier
    private File handle;
    
    // Stream du fichier
    private RandomAccessFile stream;

    /**
     * Contructeur de la classe Reader
     *
     * @param String path : le path du fichier
     */
    public Writer(String path) {

        try {
            handle = new File(path);
            
            if(handle.exists())
                throw new FileAllReadyExistException();
            
            stream = new RandomAccessFile(handle, "rw");
        } 
        catch (FileAllReadyExistException e) {
            System.out.println("\r\nError : Output file allready exist");
            System.exit(1);
        } catch (IOException e) {
            System.out.println("\r\nError : Unknow exception about the file access\r\n");
            System.exit(1);
        }
    }
    
    /**
     * Ecrit un tableau de byte dans le stream
     * 
     * @param byte[] buffer : le buffer a ecrire
     */
    public void writeBytes(byte[] buffer) {

        try {
            stream.write(buffer);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    /**
     * Ferme le stream
     */
    public void Dispose() {
        
        try {
            stream.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
