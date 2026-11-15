package n64loaderwv;

import java.awt.BorderLayout;
import java.awt.Component;
import java.io.File;
import javax.swing.JPanel;
import javax.swing.JTextField;
import docking.widgets.button.BrowseButton;
import docking.widgets.filechooser.GhidraFileChooser;
import ghidra.app.util.AddressFactoryService;
import ghidra.app.util.importer.options.StringOption;

public class FileOption extends StringOption {

	public FileOption(String name, String value, String arg) {
		super(name, value, arg, null, null, false, null);
	}

	@Override
	public Component getCustomEditorComponent(AddressFactoryService addressFactoryService) {
		JTextField textField = (JTextField) super.getCustomEditorComponent(addressFactoryService);
		textField.setColumns(25);
		BrowseButton browseButton = new BrowseButton();
		JPanel panel = new JPanel(new BorderLayout(4, 0));
		browseButton.addActionListener(e -> {
			GhidraFileChooser chooser = new GhidraFileChooser(panel);
			try {
				chooser.setTitle("Select " + getName());
				chooser.setApproveButtonText("Select");
				chooser.setLastDirectoryPreference("N64LoaderWV.LastDirectory");
				String currentPath = textField.getText().trim();
				if (!currentPath.isEmpty())
					chooser.setSelectedFile(new File(currentPath));
				File selected = chooser.getSelectedFile();
				if (selected != null)
					textField.setText(selected.getAbsolutePath());
			} finally {
				chooser.dispose();
			}
		});
		panel.add(textField, BorderLayout.CENTER);
		panel.add(browseButton, BorderLayout.EAST);
		return panel;
	}

	@Override
	public FileOption copy() {
		return new FileOption(getName(), getValue(), getArg());
	}
}