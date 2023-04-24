package kryptografia;

import javafx.event.ActionEvent;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.MenuItem;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.stage.Stage;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Random;
import java.util.ResourceBundle;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ManualInputController implements Initializable {

    public TextField keyTextField;
    public Button applyKeyButton;
    public AES aes;
    public Button randomKeyButton;
    public Button decryptButton;
    public Button encryptButton;
    public TextArea decipheredDataField;
    public TextArea encryptedDataField;
    public TextArea rawDataField;
    public TextArea rawDataAsBytesArea;
    public TextArea decipheredAsBytesField;
    public MenuItem fileModeMenuItem;

    @Override
    public void initialize(URL url, ResourceBundle resourceBundle) {
        keyTextField.textProperty().addListener((observableValue, oldValue, newValue) -> {
            Pattern p = Pattern.compile("^[a-fA-F0-9]{32}$");
            Matcher m = p.matcher(keyTextField.getText());
            boolean b = m.matches();
            applyKeyButton.setDisable(!b);
        });
    }

    public void createAESInstance(ActionEvent actionEvent) throws Exception {
        // applyKey calls this method ( knowing the key we can create AES instance )
        byte[] key = Utils.hexStringToByteArray(keyTextField.getText());
        aes = new AES(key);
        encryptButton.setDisable(false);
        decryptButton.setDisable(false);
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

    public void encryptText(ActionEvent actionEvent) {

        rawDataAsBytesArea.setText(Utils.bytesToHex(rawDataField.getText().getBytes(StandardCharsets.UTF_8)));
        byte[] encoded = aes.encode(rawDataField.getText().getBytes(StandardCharsets.UTF_8));

        encryptedDataField.setText(Utils.bytesToHex(encoded));
    }


    public synchronized void decryptText(ActionEvent actionEvent) {
        byte[] toDecrypt = Utils.hexStringToByteArray(encryptedDataField.getText());
        byte[] decrypted = aes.decode(toDecrypt);
        String hex = Utils.bytesToHex(decrypted);
        decipheredAsBytesField.setText(hex);
        byte[] bytes = new byte[0];
        try {
            bytes = Hex.decodeHex(hex.toCharArray());
        } catch (DecoderException e) {
            e.printStackTrace();
        }
        decipheredDataField.setText(new String(bytes, StandardCharsets.UTF_8));
    }

    public void changeSceneToFileMode(ActionEvent actionEvent) {
        try {
            Parent root = FXMLLoader.load(getClass().getResource("/fileView.fxml"));
            Scene scene = new Scene(root);
            Stage window = (Stage) randomKeyButton.getScene().getWindow();
            window.setScene(scene);
            window.show();
        } catch (IOException e) {
            e.printStackTrace();
        }


    }
}