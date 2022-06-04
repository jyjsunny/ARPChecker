package APA.Transformers.AnalysisSteps;


import APA.Transformers.Config;
import APA.Transformers.MCG.IntentFilter;
import APA.Transformers.apiRelate.apiClass;
import org.dom4j.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.IOException;
import java.io.StringReader;
import java.util.Objects;

public class ManifestAnalyzer {
    //manifestText
    public static String manifestText;

    static {
        try {
            manifestText = Config.apkFile.getManifestXml();//manifest得到
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    //manifestXml;
    private static  StringReader xmlReader;

    static {
        try {
            xmlReader = new StringReader(Config.apkFile.getManifestXml());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static final InputSource xmlInput = new InputSource(xmlReader);
    private static DocumentBuilder dBuilder;

    static {
        try {
            dBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
        }
    }

    private static org.w3c.dom.Document manifestXml;

    static {
        try {
            manifestXml = dBuilder.parse(xmlInput);
        } catch (SAXException | IOException e) {
            e.printStackTrace();
        }
    }


    private static final XPath xPath = XPathFactory.newInstance().newXPath();
    private static final String xpath = "/manifest/application";
    private static  Element application;

    static {
        try {
            application = (Element) xPath.evaluate(xpath, manifestXml, XPathConstants.NODE);
        } catch (XPathExpressionException e) {
            e.printStackTrace();
        }
    }

    private static final String name = application.getAttribute("android:name");
    public static apiClass applicationClass =(Objects.equals(name, ""))? null :new apiClass(name);



}
