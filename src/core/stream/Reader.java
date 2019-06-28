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

import java.io.*;
import java.nio.*;

/**
 * Classe du Reader (controleur du stream)
 * 
 * NOTE : je ne fait pas de sous exception pour les IOExceptions
 * car ce serait stupide d'imbriquer deux try pour gerer une FailToReadException
 * qui reviendrait au meme que la premiere 
 * 
 * @author r0da
 */
public class Reader {

    // Handle du fichier
    private File handle;
    
    // Stream du fichier
    private RandomAccessFile buffer;

    /**
     * Contructeur de la classe Reader
     *
     * @param String path : le path du fichier
     */
    public Reader(String path) {

        try {
            handle = new File(path);
            buffer = new RandomAccessFile(handle, "r");
        } 
        catch (FileNotFoundException e) {
            System.out.println("Error : File not found\r\n");
            System.exit(1);
        } catch (IOException e) {
            System.out.println("Error : Unknow exception about the file access\r\n");
            System.exit(1);
        }
    }

    /**
     * Renvoie le nom du fichier
     * 
     * @return le nom du fichier
     */
    public String fileName(){
        return this.handle.getName();
    }
    
    /**
     * Renvoie la taille du stream
     * 
     * @return la taille du fichier
     */
    public long size() {

        long result = 0;

        try {
            result = buffer.length();

        } catch (IOException e) {
            e.printStackTrace();
        }

        return result;
    }

    /**
     * Renvoie un byte lu a l'adresse donnée dans le stream
     * 
     * @param offset : adresse dans le stream
     * @return le byte lu
     */
    public int readByte(int offset) {

        int result = 0;

        try {
            buffer.seek(offset);

            result = buffer.readByte() & 0xFF;

        } catch (IOException e) {
            e.printStackTrace();
        }

        return result;
    }

    /**
     * Renvoie un tableau de byte lu a l'adresse donnée dans le stream
     * 
     * @param offset : adresse dans le stream
     * @param count : nombre de byte a lire
     * @return un tableau de byte
     */
    public byte[] readBytes(int offset, int count) {

        byte[] result = new byte[count];

        try {
            buffer.seek(offset);

            for (int i = 0; i < count; i++) {
                result[i] = buffer.readByte();
            }

        } catch (IOException e) {
            e.printStackTrace();
        }

        return result;
    }

    /**
     * Renvoie un string lu a l'adresse donnée dans le stream
     * 
     * @param offset : adresse dans le stream
     * @param count : nombre de charactere a lire
     * @return un string lu
     */
    public String readString(int offset, int count) {

        return new String(readBytes(offset, count));
    }

    /**
     * Lit un entier sur 4 bytes en little endian
     *
     * NOTE : merci a RandomAccessFile qui est le seul des streams de Java a
     * lire en Big endian
     *
     * Credit java2s.com
     * http://www.java2s.com/example/android/java.io/read-int-little-endian-from-randomaccessfile.html
     *
     * @param offset : l'endroit ou on lit
     * @return un int qui represente les 4 bytes lu a l'offset
     */
    public int readInt32(int offset) {

        int result = 0;

        try {

            buffer.seek(offset);

            // Little endian
            int a = buffer.readByte() & 0xFF;
            int b = buffer.readByte() & 0xFF;
            int c = buffer.readByte() & 0xFF;
            int d = buffer.readByte() & 0xFF;

            // je lis un entier sur 4 bytes
            result = (d << 24) | (c << 16) | (b << 8) | a;

        } catch (IOException e) {
            e.printStackTrace();
        }

        return result;
    }
    
    /**
     * Lit un entier sur 8 bytes en little endian
     *
     * @param offset : l'endroit ou on lit
     * @return un int qui represente les 8 bytes lu a l'offset
     */
    public int readInt64(int offset) {

        int result = 0;

        try {

            buffer.seek(offset);

            // Little endian
            int a = buffer.readByte() & 0xFF;
            int b = buffer.readByte() & 0xFF;
            int c = buffer.readByte() & 0xFF;
            int d = buffer.readByte() & 0xFF;
            int e = buffer.readByte() & 0xFF;
            int f = buffer.readByte() & 0xFF;
            int g = buffer.readByte() & 0xFF;
            int h = buffer.readByte() & 0xFF;

            // je lis un entier sur 8 bytes
            result = (h << 56) | (g << 48) | (f  << 40) | (e  << 32) |
                     (d << 24) | (c << 16) | (b  <<  8) | a;

        } catch (IOException e) {
            e.printStackTrace();
        }

        return result;
    }

    /*
     * Lit un entier sur 2 bytes en little endian
     *
     * NOTE : pour une raison que j'ignore, la convertion manuelle 
     * des bytes vers du little endian ne marche pas. J'ai donc utilisé 
     * une fonction toute faite
     *
     * @param int offset : l'endroit ou on lit
     * @return un int qui represente les 2 bytes lu a l'offset
     */
    public int readInt16(int offset) {

        int result = 0;

        try {

            buffer.seek(offset);

            ByteBuffer wrapper = ByteBuffer.wrap(new byte[]{buffer.readByte(), buffer.readByte()});

            wrapper.order(ByteOrder.LITTLE_ENDIAN);

            result = wrapper.getShort();

        } catch (IOException e) {
            e.printStackTrace();
        }

        return result;
    }
    
    /**
     * Ferme le stream
     */
    public void Dispose() {
        
        try {
            buffer.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
