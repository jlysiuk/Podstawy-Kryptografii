package kryptografia;

import javafx.event.ActionEvent;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.MenuItem;
import javafx.scene.control.TextField;
import javafx.scene.paint.Color;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.Random;
import java.util.ResourceBundle;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class FileInputController implements Initializable {
    public Label notificationEncryptionLabel;
    public Button randomKeyButton;
    public TextField keyTextField;
    public Button applyKeyButton;
    public Label notificationDecryptionLabel;
    public MenuItem manualMenuItem;
    public Button decryptButton;
    public Button encryptButton;
    AES aes;

    @Override
    public void initialize(URL url, ResourceBundle resourceBundle) {
        keyTextField.textProperty().addListener((observableValue, oldValue, newValue) -> {
            Pattern p = Pattern.compile("^[a-fA-F0-9]{32}$");
            Matcher m = p.matcher(keyTextField.getText());
            boolean b = m.matches();
            applyKeyButton.setDisable(!b);
        });
    }

    public void generateRandomKey(ActionEvent actionEvent) {
        String literals = "ABCDEF09876543210";
        Random random = new Random();
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < 32; i++) {
            builder.append(literals.charAt(random.nextInt(literals.length())));
        }
        keyTextField.textProperty().set(builder.toString());
    }

    public void createAESInstance(ActionEvent actionEvent) throws Exception {
        // applyKey calls this method ( knowing the key we can create AES instance )
        byte[] key = Utils.hexStringToByteArray(keyTextField.getText());
        aes = new AES(key);
        encryptButton.setDisable(false);
        decryptButton.setDisable(false);
    }

    public void changeSceneToManual(ActionEvent actionEvent) {
        try {
            Parent root = FXMLLoader.load(getClass().getResource("/manualView.fxml"));
            Scene scene = new Scene(root);
            Stage window = (Stage) randomKeyButton.getScene().getWindow();
            window.setScene(scene);
            window.show();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void chooseFileAndEncrypt(ActionEvent actionEvent) {
        FileChooser fileChooser = new FileChooser();
        File selectedFile = fileChooser.showOpenDialog(new Stage());
        try {
            byte[] fileBytes = FileUtils.readFileToByteArray(selectedFile);
            byte[] encodedBytes = aes.encode(fileBytes);
            File destination = fileChooser.showSaveDialog(new Stage());
            FileUtils.writeByteArrayToFile(destination, encodedBytes);
            notificationEncryptionLabel.setTextFill(Color.web("#00FF00"));
            notificationEncryptionLabel.setText("File encrypted successfully");
        } catch (IOException e) {
            e.printStackTrace();
            notificationEncryptionLabel.setTextFill(Color.web("#FF0000"));
            notificationEncryptionLabel.setText("Error occured :(");
        }
    }

    public void chooseFileAndDecrypt(ActionEvent actionEvent) {
        FileChooser fileChooser = new FileChooser();
        File selectedFile = fileChooser.showOpenDialog(new Stage());
        try {
            byte[] fileBytes = FileUtils.readFileToByteArray(selectedFile);
            byte[] decodedBytes = aes.decode(fileBytes);
            File destination = fileChooser.showSaveDialog(new Stage());
            FileUtils.writeByteArrayToFile(destination, decodedBytes);
            notificationDecryptionLabel.setTextFill(Color.web("#00FF00"));
            notificationDecryptionLabel.setText("File decrypted successfully");
        } catch (IOException e) {
            e.printStackTrace();
            notificationDecryptionLabel.setTextFill(Color.web("#FF0000"));
            notificationDecryptionLabel.setText("Error occured :(");
        }
    }
}
