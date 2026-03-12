import javax.swing.*;
import javax.swing.border.*;
import javax.swing.table.*;
import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;
import java.text.SimpleDateFormat;

public class FirewallSimulator extends JFrame {
    private DefaultTableModel trafficModel, rulesModel;
    private JTable trafficTable, rulesTable;
    private JLabel blockedCount, allowedCount, totalCount;
    private JTextArea logArea;
    private List<FirewallRule> rules = new ArrayList<>();
    private javax.swing.Timer trafficGenerator;
    private int blocked = 0, allowed = 0;
    
    public FirewallSimulator() {
        setTitle("Firewall Simulator - Network Traffic Monitor");
        setSize(1200, 800);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        
        // Modern look and feel
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        initializeDefaultRules();
        initComponents();
        startTrafficGeneration();
    }
    
    private void initComponents() {
        setLayout(new BorderLayout(10, 10));
        getContentPane().setBackground(new Color(240, 240, 245));
        
        // Top Panel - Header
        JPanel headerPanel = createHeaderPanel();
        add(headerPanel, BorderLayout.NORTH);
        
        // Center Panel - Split between traffic and rules
        JSplitPane centerSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        centerSplit.setDividerLocation(700);
        centerSplit.setLeftComponent(createTrafficPanel());
        centerSplit.setRightComponent(createRulesPanel());
        add(centerSplit, BorderLayout.CENTER);
        
        // Bottom Panel - Logs
        add(createLogPanel(), BorderLayout.SOUTH);
    }
    
    private JPanel createHeaderPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(new Color(41, 128, 185));
        panel.setBorder(BorderFactory.createEmptyBorder(15, 20, 15, 20));
        
        JLabel title = new JLabel("Firewall Simulator");
        title.setFont(new Font("Dialog", Font.BOLD, 28));
        title.setForeground(Color.WHITE);
        panel.add(title, BorderLayout.WEST);
        
        // Statistics Panel
        JPanel statsPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 20, 0));
        statsPanel.setOpaque(false);
        
        blockedCount = createStatLabel("Blocked: 0", new Color(231, 76, 60));
        allowedCount = createStatLabel("Allowed: 0", new Color(46, 204, 113));
        totalCount = createStatLabel("Total: 0", Color.WHITE);
        
        statsPanel.add(blockedCount);
        statsPanel.add(allowedCount);
        statsPanel.add(totalCount);
        panel.add(statsPanel, BorderLayout.EAST);
        
        return panel;
    }
    
    private JLabel createStatLabel(String text, Color color) {
        JLabel label = new JLabel(text);
        label.setFont(new Font("Segoe UI", Font.BOLD, 16));
        label.setForeground(color);
        return label;
    }
    
    private JPanel createTrafficPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBackground(Color.WHITE);
        panel.setBorder(createTitledBorder("Network Traffic Monitor"));
        
        // Traffic table
        String[] columns = {"Time", "Source IP", "Dest IP", "Port", "Protocol", "Status"};
        trafficModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int col) { 
                return false; 
            }
        };
        
        trafficTable = new JTable(trafficModel);
        trafficTable.setRowHeight(28);
        trafficTable.setFont(new Font("Monospaced", Font.PLAIN, 12));
        trafficTable.getTableHeader().setFont(new Font("Segoe UI", Font.BOLD, 12));
        trafficTable.getTableHeader().setBackground(new Color(52, 73, 94));
        trafficTable.getTableHeader().setForeground(Color.WHITE);
        trafficTable.setSelectionBackground(new Color(189, 195, 199));
        
        // Custom renderer for status column
        trafficTable.getColumnModel().getColumn(5).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, 
                    boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                if (value != null) {
                    String status = value.toString();
                    if (!isSelected) {
                        if (status.contains("BLOCKED")) {
                            c.setBackground(new Color(255, 230, 230));
                            c.setForeground(new Color(192, 57, 43));
                        } else {
                            c.setBackground(new Color(230, 255, 230));
                            c.setForeground(new Color(39, 174, 96));
                        }
                    }
                    ((JLabel)c).setFont(new Font("Segoe UI", Font.BOLD, 11));
                }
                return c;
            }
        });
        
        JScrollPane scrollPane = new JScrollPane(trafficTable);
        panel.add(scrollPane, BorderLayout.CENTER);
        
        // Control buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        buttonPanel.setBackground(Color.WHITE);
        
        JButton clearBtn = createStyledButton("Clear Traffic", new Color(231, 76, 60));
        clearBtn.addActionListener(e -> {
            trafficModel.setRowCount(0);
            blocked = 0;
            allowed = 0;
            updateStatistics();
        });
        
        JButton pauseBtn = createStyledButton("Pause/Resume", new Color(241, 196, 15));
        pauseBtn.addActionListener(e -> {
            if (trafficGenerator.isRunning()) {
                trafficGenerator.stop();
            } else {
                trafficGenerator.start();
            }
        });
        
        buttonPanel.add(pauseBtn);
        buttonPanel.add(clearBtn);
        panel.add(buttonPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    private JPanel createRulesPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBackground(Color.WHITE);
        panel.setBorder(createTitledBorder("Firewall Rules"));
        
        // Rules table
        String[] columns = {"IP/Range", "Port", "Protocol", "Action"};
        rulesModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int col) { 
                return false; 
            }
        };
        
        rulesTable = new JTable(rulesModel);
        rulesTable.setRowHeight(28);
        rulesTable.setFont(new Font("Monospaced", Font.PLAIN, 12));
        rulesTable.getTableHeader().setFont(new Font("Segoe UI", Font.BOLD, 12));
        rulesTable.getTableHeader().setBackground(new Color(52, 73, 94));
        rulesTable.getTableHeader().setForeground(Color.WHITE);
        
        loadRulesToTable();
        
        JScrollPane scrollPane = new JScrollPane(rulesTable);
        panel.add(scrollPane, BorderLayout.CENTER);
        
        // Rule management buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        buttonPanel.setBackground(Color.WHITE);
        
        JButton addBtn = createStyledButton("Add Rule", new Color(46, 204, 113));
        addBtn.addActionListener(e -> showAddRuleDialog());
        
        JButton deleteBtn = createStyledButton("Delete Rule", new Color(231, 76, 60));
        deleteBtn.addActionListener(e -> deleteSelectedRule());
        
        buttonPanel.add(addBtn);
        buttonPanel.add(deleteBtn);
        panel.add(buttonPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    private JPanel createLogPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBackground(Color.WHITE);
        panel.setBorder(createTitledBorder("Activity Log"));
        panel.setPreferredSize(new Dimension(0, 150));
        
        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        logArea.setBackground(new Color(44, 62, 80));
        logArea.setForeground(new Color(236, 240, 241));
        
        JScrollPane scrollPane = new JScrollPane(logArea);
        panel.add(scrollPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    private Border createTitledBorder(String title) {
        TitledBorder border = BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(new Color(189, 195, 199), 2),
            title,
            TitledBorder.LEFT,
            TitledBorder.TOP,
            new Font("Segoe UI", Font.BOLD, 14),
            new Color(52, 73, 94)
        );
        return BorderFactory.createCompoundBorder(
            BorderFactory.createEmptyBorder(10, 10, 10, 10),
            border
        );
    }
    
    private JButton createStyledButton(String text, Color color) {
        JButton btn = new JButton(text);
        btn.setFont(new Font("Segoe UI", Font.BOLD, 12));
        btn.setBackground(color);
        btn.setForeground(Color.WHITE);
        btn.setFocusPainted(false);
        btn.setBorder(BorderFactory.createEmptyBorder(8, 15, 8, 15));
        btn.setCursor(new Cursor(Cursor.HAND_CURSOR));
        btn.setOpaque(true);
        btn.setBorderPainted(false);
        
        btn.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                btn.setBackground(color.darker());
            }
            @Override
            public void mouseExited(MouseEvent e) {
                btn.setBackground(color);
            }
        });
        
        return btn;
    }
    
    private void initializeDefaultRules() {
        rules.add(new FirewallRule("192.168.1.100", 80, "HTTP", "BLOCK"));
        rules.add(new FirewallRule("10.0.0.0/8", 22, "SSH", "BLOCK"));
        rules.add(new FirewallRule("*", 443, "HTTPS", "ALLOW"));
        rules.add(new FirewallRule("172.16.0.0/12", 3389, "RDP", "BLOCK"));
    }
    
    private void loadRulesToTable() {
        rulesModel.setRowCount(0);
        for (FirewallRule rule : rules) {
            rulesModel.addRow(new Object[]{
                rule.ip, rule.port, rule.protocol, rule.action
            });
        }
    }
    
    private void showAddRuleDialog() {
        JDialog dialog = new JDialog(this, "Add Firewall Rule", true);
        dialog.setLayout(new GridLayout(5, 2, 10, 10));
        dialog.setSize(400, 250);
        dialog.setLocationRelativeTo(this);
        
        JTextField ipField = new JTextField("192.168.1.1");
        JTextField portField = new JTextField("80");
        JTextField protocolField = new JTextField("HTTP");
        JComboBox<String> actionBox = new JComboBox<>(new String[]{"ALLOW", "BLOCK"});
        
        dialog.add(new JLabel("IP Address/Range:"));
        dialog.add(ipField);
        dialog.add(new JLabel("Port:"));
        dialog.add(portField);
        dialog.add(new JLabel("Protocol:"));
        dialog.add(protocolField);
        dialog.add(new JLabel("Action:"));
        dialog.add(actionBox);
        
        JButton addBtn = createStyledButton("Add", new Color(46, 204, 113));
        JButton cancelBtn = createStyledButton("Cancel", new Color(149, 165, 166));
        
        addBtn.addActionListener(e -> {
            try {
                int port = Integer.parseInt(portField.getText());
                FirewallRule rule = new FirewallRule(
                    ipField.getText(),
                    port,
                    protocolField.getText(),
                    actionBox.getSelectedItem().toString()
                );
                rules.add(rule);
                loadRulesToTable();
                log("Added new rule: " + rule);
                dialog.dispose();
            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(dialog, "Invalid port number!");
            }
        });
        
        cancelBtn.addActionListener(e -> dialog.dispose());
        
        dialog.add(addBtn);
        dialog.add(cancelBtn);
        dialog.setVisible(true);
    }
    
    private void deleteSelectedRule() {
        int row = rulesTable.getSelectedRow();
        if (row >= 0) {
            rules.remove(row);
            loadRulesToTable();
            log("Deleted rule at row " + (row + 1));
        } else {
            JOptionPane.showMessageDialog(this, "Please select a rule to delete!");
        }
    }
    
    private void startTrafficGeneration() {
        trafficGenerator = new javax.swing.Timer(2000, e -> generateRandomTraffic());
        trafficGenerator.start();
    }
    
    private void generateRandomTraffic() {
        Random rand = new Random();
        String[] protocols = {"HTTP", "HTTPS", "SSH", "FTP", "RDP", "DNS"};
        int[] ports = {80, 443, 22, 21, 3389, 53, 8080, 3306};
        
        String srcIP = generateRandomIP();
        String destIP = generateRandomIP();
        int port = ports[rand.nextInt(ports.length)];
        String protocol = protocols[rand.nextInt(protocols.length)];
        
        boolean isBlocked = checkFirewallRules(destIP, port);
        String status = isBlocked ? "BLOCKED" : "ALLOWED";
        
        if (isBlocked) {
            blocked++;
            log("BLOCKED traffic from " + srcIP + " to " + destIP + ":" + port);
        } else {
            allowed++;
        }
        
        SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss");
        String time = sdf.format(new Date());
        
        trafficModel.insertRow(0, new Object[]{time, srcIP, destIP, port, protocol, status});
        
        if (trafficModel.getRowCount() > 100) {
            trafficModel.removeRow(100);
        }
        
        updateStatistics();
    }
    
    private boolean checkFirewallRules(String ip, int port) {
        for (FirewallRule rule : rules) {
            if (rule.matches(ip, port) && rule.action.equals("BLOCK")) {
                return true;
            }
        }
        return false;
    }
    
    private String generateRandomIP() {
        Random rand = new Random();
        return rand.nextInt(256) + "." + rand.nextInt(256) + "." + 
               rand.nextInt(256) + "." + rand.nextInt(256);
    }
    
    private void updateStatistics() {
        int total = blocked + allowed;
        blockedCount.setText("Blocked: " + blocked);
        allowedCount.setText("Allowed: " + allowed);
        totalCount.setText("Total: " + total);
    }
    
    private void log(String message) {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String timestamp = sdf.format(new Date());
        logArea.append("[" + timestamp + "] " + message + "\n");
        logArea.setCaretPosition(logArea.getDocument().getLength());
    }
    
    // Firewall Rule Class
    class FirewallRule {
        String ip;
        int port;
        String protocol;
        String action;
        
        FirewallRule(String ip, int port, String protocol, String action) {
            this.ip = ip;
            this.port = port;
            this.protocol = protocol;
            this.action = action;
        }
        
        boolean matches(String testIP, int testPort) {
            if (ip.equals("*")) return port == testPort;
            if (ip.contains("/")) {
                // CIDR notation - simplified matching
                String baseIP = ip.split("/")[0];
                String testPrefix = testIP.substring(0, testIP.lastIndexOf("."));
                String rulePrefix = baseIP.substring(0, baseIP.lastIndexOf("."));
                return testPrefix.equals(rulePrefix) && port == testPort;
            }
            return ip.equals(testIP) && port == testPort;
        }
        
        @Override
        public String toString() {
            return ip + ":" + port + " (" + protocol + ") - " + action;
        }
    }
    
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            FirewallSimulator simulator = new FirewallSimulator();
            simulator.setVisible(true);
        });
    }
}
