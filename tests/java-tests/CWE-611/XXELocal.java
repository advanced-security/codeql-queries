import java.io.File;
import java.io.FileInputStream;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.xml.sax.InputSource;
import org.xml.sax.XMLReader;

public class XMLParser {
    public static void main(String[] args) throws Exception {
        // Get user input from file
        File file = new File("input.xml");
        FileInputStream inputStream = new FileInputStream(file);
        InputSource inputSource = new InputSource(inputStream);

        // Get XML reader
        XMLReader xmlReader = getXMLReader();

        // Parse XML
        SAXParserFactory saxParserFactory = SAXParserFactory.newInstance();
        SAXParser saxParser = saxParserFactory.newSAXParser();
        saxParser.parse(inputSource, xmlReader);
    }

    private static XMLReader getXMLReader() throws Exception {
        // Create XML reader
        SAXParserFactory saxParserFactory = SAXParserFactory.newInstance();
        SAXParser saxParser = saxParserFactory.newSAXParser();
        XMLReader xmlReader = saxParser.getXMLReader();

        // Set properties for XML reader
        xmlReader.setFeature("http://xml.org/sax/features/external-general-entities", false);
        xmlReader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        xmlReader.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

        return xmlReader;
    }
}