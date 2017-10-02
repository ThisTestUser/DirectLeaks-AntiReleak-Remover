package me.itzsomebody.injectorremover;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;

import org.objectweb.asm.Attribute;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.Handle;

@SuppressWarnings("serial")
public class InjectorRemover extends JFrame {
	
    private JTextField field;
    
    public static void main(String[] args) {
        createGUI();
    }
	
	private static void createGUI() {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                try {
                    UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
                }
                catch (Exception ex) {}
                InjectorRemover remover = new InjectorRemover();
                remover.setTitle("Anti-Releak Remover");
                remover.setResizable(false);
                remover.setSize(400, 100);
                remover.setLocationRelativeTo(null);
                remover.setDefaultCloseOperation(3);
                remover.getContentPane().setLayout(new FlowLayout());
                JLabel label = new JLabel("Select File:");
                remover.field = new JTextField();
                remover.field.setEditable(true);
                remover.field.setColumns(18);
                JButton selectButton = new JButton("Select");
                selectButton.setToolTipText("Select jar file");
                selectButton.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        JFileChooser chooser = new JFileChooser();
                        if (remover.field.getText() != null && !remover.field.getText().isEmpty()) {
                            chooser.setSelectedFile(new File(remover.field.getText()));
                        }
                        chooser.setMultiSelectionEnabled(false);
                        chooser.setFileSelectionMode(0);
                        int result = chooser.showOpenDialog(remover);
                        if (result == 0) {
                            SwingUtilities.invokeLater(new Runnable() {
                                @Override
                                public void run() {
                                    remover.field.setText(chooser.getSelectedFile().getAbsolutePath());
                                }
                            });
                        }
                    }
                });
                JButton startButton = new JButton("Start");
                startButton.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        if (remover.field.getText() == null || remover.field.getText().isEmpty() || !remover.field.getText().endsWith(".jar")) {
                            JOptionPane.showMessageDialog(null, "You must select a valid jar file!", "Error", 0);
                            return;
                        }
                        File output = null;
                        try {
                            File input = new File(remover.field.getText());
                            if (!input.getName().endsWith(".jar")) {
                                throw new IllegalArgumentException("File must be a jar.");
                            }
                            if (!input.exists()) {
                                throw new FileNotFoundException("The file " + input.getName() + " doesn't exist.");
                            }
                            output = new File(String.format("%s-Output.jar", input.getAbsolutePath().substring(0, input.getAbsolutePath().lastIndexOf("."))));
                            if (output.exists()) {
                                output.delete();
                            }
                            process(input, output, 1);
                            checkFile(output);
                            JOptionPane.showMessageDialog(null, "Done: " + output.getAbsolutePath(), "Done", 1);
                        }
                        catch (Throwable t) {
                            JOptionPane.showMessageDialog(null, t, "Error", 0);
                            t.printStackTrace();
                            if (output != null) {
                                output.delete();
                            }
                        }
                        finally {
                            SwingUtilities.invokeLater(new Runnable() {
                                @Override
                                public void run() {
                                    remover.field.setText("");
                                }
                            });
                        }
                    }
                });
                JPanel panel = new JPanel(new FlowLayout());
                panel.add(label);
                panel.add(remover.field);
                panel.add(selectButton);
                JPanel panel2 = new JPanel(new FlowLayout());
                panel2.add(startButton);
                JPanel border = new JPanel(new BorderLayout());
                border.add(panel, "North");
                border.add(panel2, "South");
                remover.getContentPane().add(border);
                remover.setVisible(true);
            }
        });
    }
	
	private static void checkFile(File jarFile) throws Throwable {
        if (!jarFile.exists()) {
            throw new IllegalStateException("Output file not found.");
        }
    }
	
	private static void writeToFile(ZipOutputStream outputStream, InputStream inputStream) throws Throwable {
        byte[] buffer = new byte[4096];
        try {
            while (inputStream.available() > 0) {
                int data = inputStream.read(buffer);
                outputStream.write(buffer, 0, data);
            }
        }
        finally {
            inputStream.close();
            outputStream.closeEntry();
        }
    }
    
    private static void process(File jarFile, File outputFile, int mode) throws Throwable {
        ZipFile zipFile = new ZipFile(jarFile);
        Enumeration<? extends ZipEntry> entries = zipFile.entries();
        ZipOutputStream out = new ZipOutputStream(new FileOutputStream(outputFile));
        try {
            while (entries.hasMoreElements()) {
                ZipEntry entry = (ZipEntry)entries.nextElement();
                if (!entry.isDirectory() && entry.getName().endsWith(".class")) {
                    try (InputStream in = zipFile.getInputStream(entry)) {
                        ClassReader cr = new ClassReader(in);
                        ClassNode classNode = new ClassNode();
                        cr.accept(classNode, 0);
                        if (mode == 1) {
                        	invokeDynamicTransfomer(classNode);
                            stringEncryptionTransformer(classNode);
                            removeObsoleteInjection(classNode);
                            removeBootstrapMethod(classNode);
                            removeXORMethod(classNode);
                            attrRemover(classNode);
                            signatureRemover(classNode);
                            
                            ClassWriter cw = new ClassWriter(0);
                            classNode.accept(cw);
                            ZipEntry newEntry = new ZipEntry(entry.getName());
                            newEntry.setTime(System.currentTimeMillis());
                            out.putNextEntry(newEntry);
                            writeToFile(out, new ByteArrayInputStream(cw.toByteArray()));
                        }
                    }
                }
                else {
                	if (mode == 1) {
                		entry.setTime(System.currentTimeMillis());
                        out.putNextEntry(entry);
                        writeToFile(out, zipFile.getInputStream(entry));
                	}
                }
            }
        }
        finally {
            zipFile.close();
            if (out != null) {
                out.close();
            }
        }
    }
    
    private static void removeObsoleteInjection(ClassNode classNode) {
    	Iterator<MethodNode> iterator = classNode.methods.iterator();
        while (iterator.hasNext()) {
            MethodNode methodNode = iterator.next();
            if (methodNode.name.equalsIgnoreCase("onEnable") || methodNode.name.equalsIgnoreCase("onLoad")) {
                InsnList insnNodes = methodNode.instructions;
                AbstractInsnNode insnNode = insnNodes.get(0);
                if (insnNode.getOpcode() == 184 && ((MethodInsnNode)insnNode).name.equalsIgnoreCase("\u0970") && ((MethodInsnNode)insnNode).desc.equalsIgnoreCase("()V")) {
                	insnNodes.remove(insnNode);
                }
                if (insnNode.getOpcode() == 184 && ((MethodInsnNode)insnNode).name.equalsIgnoreCase("\u0971") && ((MethodInsnNode)insnNode).desc.equalsIgnoreCase("()V")) {
                	insnNodes.remove(insnNode);
                }
            }
            if (methodNode.name.equalsIgnoreCase("\u0970") && methodNode.desc.equalsIgnoreCase("()V") && methodNode.access == 4170) {
            	iterator.remove();
            }
            if (methodNode.name.equalsIgnoreCase("\u0971") && methodNode.desc.equalsIgnoreCase("()V") && methodNode.access == 4170) {
            	iterator.remove();
            }
        }
    }
    
    private static void removeBootstrapMethod(ClassNode classNode) {
    	Iterator<MethodNode> iterator = classNode.methods.iterator();
        while (iterator.hasNext()) {
        	MethodNode methodNode = iterator.next();
        	if (methodNode.desc.equalsIgnoreCase("(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/Class;Ljava/lang/String;I)Ljava/lang/invoke/CallSite;")) {
            	iterator.remove();
            }
        }
    	
    	for (Iterator<FieldNode> it = classNode.fields.iterator(); it.hasNext() ;) {
    		FieldNode fieldNode = it.next();
    		if (fieldNode.access == 9 && fieldNode.desc.equalsIgnoreCase("I")) {
    			it.remove();
    		} else if (fieldNode.access == 9 && fieldNode.desc.equalsIgnoreCase("Ljava/lang/String;")) {
    			it.remove();
    		}
    	}
    }
    
    private static void removeXORMethod(ClassNode classNode) {
    	Iterator<MethodNode> iterator = classNode.methods.iterator();
        while (iterator.hasNext()) {
        	MethodNode methodNode = iterator.next();
            if (classNode.superName.equals("org/bukkit/plugin/java/JavaPlugin") || classNode.superName.equals("net/md_5/bungee/api/plugin/Plugin")) {
            	if (methodNode.name.equalsIgnoreCase("\u0972") && methodNode.access == 4170 && methodNode.desc.equalsIgnoreCase("(Ljava/lang/String;)Ljava/lang/String;")) {
            		iterator.remove();
            	}
            }
        }
    }
    
    private static void invokeDynamicTransfomer(ClassNode classNode) {
    	String bootstrapDesc = "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/Class;Ljava/lang/String;I)Ljava/lang/invoke/CallSite;";
    	for (MethodNode methodNode : classNode.methods) {
    		InsnList copy = copyInsnList(methodNode.instructions);
            for (int i = 0; i < copy.size(); i++) {
                AbstractInsnNode insn = copy.get(i);
                if (insn instanceof InvokeDynamicInsnNode) {
                	InvokeDynamicInsnNode dyn = (InvokeDynamicInsnNode) insn;
                	if (dyn.bsmArgs.length == 3) {
                		Handle bootstrap = dyn.bsm;
                		if (bootstrap.getDesc().equals(bootstrapDesc)) {
                			int legitOpCode = (Integer) dyn.bsmArgs[2];
                			String legitOwner = dyn.bsmArgs[0].toString().substring(1, dyn.bsmArgs[0].toString().length() - 1);
                			String legitDesc = dyn.bsmArgs[1].toString();
                			MethodInsnNode replacement;
                			if (legitOpCode == 182) { // INVOKEVIRTUAL
                				replacement = new MethodInsnNode(182, legitOwner, decryptionArray(dyn.name), decryptionArray(legitDesc), false);
                				methodNode.instructions.set(insn, replacement);
                			} else if (legitOpCode == 184) { // INVOKESTATIC
                				replacement = new MethodInsnNode(184, legitOwner, decryptionArray(dyn.name), decryptionArray(legitDesc), false);
                				methodNode.instructions.set(insn, replacement);
                			}
                		}
                	}
                }
            }
    	}
    }
    
    public static InsnList copyInsnList(InsnList original) {
        InsnList newInsnList = new InsnList();

        for (AbstractInsnNode insn = original.getFirst(); insn != null; insn = insn.getNext()) {
            newInsnList.add(insn);
        }

        return newInsnList;
    }
    
    private static void stringEncryptionTransformer(ClassNode classNode) {
    	if (classNode.superName.equals("org/bukkit/plugin/java/JavaPlugin") || classNode.superName.equals("net/md_5/bungee/api/plugin/Plugin")) {
    		for (MethodNode methodNode : classNode.methods) {
    			InsnList nodes = methodNode.instructions;
    			for (int i = 0; i < nodes.size(); i++) {
    				AbstractInsnNode instruction = nodes.get(i);
    				if (instruction instanceof LdcInsnNode) {
    					if (instruction.getNext() instanceof MethodInsnNode) {
    						LdcInsnNode ldc = (LdcInsnNode) instruction;
                            MethodInsnNode methodinsnnode = (MethodInsnNode) ldc.getNext();
                            if (ldc.cst instanceof String) {
                            	if (methodinsnnode.name.equalsIgnoreCase("\u0972") && methodinsnnode.desc.equalsIgnoreCase("(Ljava/lang/String;)Ljava/lang/String;")) {
                            		methodNode.instructions.remove(methodinsnnode);
                            		ldc.cst = decryptionArray((String)ldc.cst);
                            	}
                            }
    					}
    				}
    			}
    		}
        }
    }
    
    private static String decryptionArray(String msg) {
		try {
			char[] array = { '\u4831', '\u2384', '\u2385', '\u9812', '\u9123', '\u4581', '\u0912', '\u3421', '\u0852', '\u0723' };
            char[] charArray = msg.toCharArray();
            char[] array2 = new char[charArray.length];
            for (int i = 0; i < charArray.length; ++i) {
                array2[i] = (char)(charArray[i] ^ array[i % array.length]);
            }
            return new String(array2);
        }
        catch (Exception ex) {
            return msg;
        }
    }
    
    private static void signatureRemover(ClassNode classNode) {
    	if (classNode.superName.equals("org/bukkit/plugin/java/JavaPlugin") || classNode.superName.equals("net/md_5/bungee/api/plugin/Plugin")) {
    		classNode.signature = null;
        }
    }
    
    private static void attrRemover(ClassNode classNode) {
    	if (classNode.superName.equals("org/bukkit/plugin/java/JavaPlugin") || classNode.superName.equals("net/md_5/bungee/api/plugin/Plugin")) {
    		if (classNode.attrs != null) {
                Iterator<Attribute> attributeIterator = classNode.attrs.iterator();
                while (attributeIterator.hasNext()) {
                    Attribute attribute = attributeIterator.next();
                    if (attribute.type.equalsIgnoreCase("PluginVersion")) {
                        attributeIterator.remove();
                    }
                    if (attribute.type.equalsIgnoreCase("CompileVersion")) {
                        attributeIterator.remove();
                    }
                }
            }
        }
    }
}
