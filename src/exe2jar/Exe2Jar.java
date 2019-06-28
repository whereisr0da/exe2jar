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

package exe2jar;

import core.paterns.HideVersion;
import core.paterns.EncryptedVersion;
import core.paterns.VanillaVersion;
import core.paterns.x64;
import core.paterns.x32;
import core.extractor.*;
import core.pefile.*;
import core.stream.Writer;
import core.signature.*;
import java.util.ArrayList;

public class Exe2Jar {

    static PE executable;
    static LicenceInfo info;
    static Unpacker unpack;
    
    // Checkers
    static CommunCheck jar2exePaterns;
    static CommunCheck jar2exeVariants;
    
    // Liste des paterns
    static ArrayList<CommunPatern> paternList;
    // Liste des variants
    static ArrayList<CommunPatern> variantList;

    /**
     * Entrypoint du programme
     * 
     * @param args the command line arguments
     */
    public static void main(String[] args) {

        System.out.println("Exe2Jar 0.1 by r0da\r\n");

        interpretCommands(args);
    }

    /**
     * Initialisation des signatures
     */
    public static void initSignatures() {

        paternList = new ArrayList<>();
        variantList = new ArrayList<>();

        paternList.add(new x32());
        paternList.add(new x64());

        variantList.add(new EncryptedVersion());
        variantList.add(new HideVersion());
        variantList.add(new VanillaVersion());

        jar2exePaterns = new CommunCheck(paternList, "Result           : jar2exe ");
        jar2exeVariants = new CommunCheck(variantList, "Type             : ");
    }

    /**
     * Verification des signatures
     */
    public static void checkingSignatures() {

        initSignatures();

        if (!jar2exePaterns.invoke(executable)) {
            System.out.println("Ce n'est pas un executable jar2exe");
            System.exit(0);
        }

        if (!jar2exeVariants.invoke(executable)) {
            System.out.println("variante inconnu");
            System.exit(0);
        }
    }

    /**
     * Recuperation du fichier jar
     * 
     * @param String file : path fichier
     * @param String output : path de l'output
     */
    public static void getJarFile(String file, String output) {

        executable = new PE(file);

        checkingSignatures();

        info = new LicenceInfo(executable);

        unpack = new Unpacker(executable, info);

        System.out.println("Supported        : " + unpack.supported());

        // je ne fais pas d'exception car j'utiliser la valeur de retour 
        if (!unpack.supported()) {
            System.out.println("\r\nThis variant is not supported");
            System.exit(0);
        }

        byte[] jarFile = unpack.getJarFileFromResource();

        Writer writer = new Writer(output);

        // On ecrit le fichier java
        writer.writeBytes(jarFile);

        int size = jarFile.length;
        String type = "bytes";

        if (size > 1000) {
            size /= 1000;
            type = "Mo";
        }

        System.out.println("\r\nFile successfully extracted about " + size + " " + type);

        writer.Dispose();
        
        executable.reader.Dispose();
    }

    /**
     * Recuperation des informations du fichier jar
     * 
     * @param String path : path fichier
     */
    public static void getInfo(String path) {

        executable = new PE(path);

        checkingSignatures();

        info = new LicenceInfo(executable);

        unpack = new Unpacker(executable, info);

        System.out.println("Supported        : " + unpack.supported());
        System.out.println("Machine ID       : " + info.getMachineId());
        System.out.println("Creation Date    : " + info.getCreationDate());
        System.out.println("Expiration Date  : " + info.getExpirationDate());
        System.out.println("Main Class       : " + info.getMainClass());
        System.out.println("JRE Version      : " + info.getJreVersion());
        System.out.println("Checked MD5      : " + info.getMD5Check());

        executable.reader.Dispose();
    }
    
    /**
     * Interprete les arguments du l'execution du programme
     * 
     * @param String[] args : arguments
     */
    public static void interpretCommands(String[] args) {

        if (args.length < 1) {
            printInfo();
            System.exit(0);
        }

        if (args[0].toLowerCase().equals("-h")) {
            printInfo();
        } else if (args.length == 2 && args[0].toLowerCase().equals("-i")) {
            getInfo(args[1]);
        } else if (args.length == 3 && args[0].toLowerCase().equals("-u")) {
            getJarFile(args[2], args[1]);
        } else {
            System.out.println("Invalid arguments");
        }

        System.exit(0);
    }

    /**
     * Affiche les infos
     */
    public static void printInfo() {
        System.out.println("Usages : Exe2Jar.jar <option> <file>");
        System.out.println("        -h                     : Show usages");
        System.out.println("        -i <file>              : Show informations about the executable");
        System.out.println("        -u <outputFile> <file> : Unpack the jar file from the executable");
    }
}
