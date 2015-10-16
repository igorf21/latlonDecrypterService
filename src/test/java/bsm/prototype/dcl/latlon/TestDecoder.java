package bsm.prototype.dcl.latlon;

import static org.junit.Assert.*;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import bsm.dcl.config.dal.entities.DataDefinition;
import bsm.dcl.config.dal.entities.UnitDataDefinition;
import bsm.dcl.messaging.Common;
import bsm.dcl.messaging.LocomotiveMonitoringUnit;
import bsm.dcl.messaging.MessageControl;
import bsm.dcl.messaging.SolarTrackingUnit;
import bsm.dcl.messaging.SensorRefrigiration;
import bsm.dcl.messaging.UnitMessage;
import bsm.decrypt.latlon.Decrypter;

public class TestDecoder {

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
	}

	@AfterClass
	public static void tearDownAfterClass() throws Exception {
	}

	@Before
	public void setUp() throws Exception {
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public final void testDecrypt() {
		String encryptedMsg1 = "0F05974D004D4404B204DE4444F1CC411A47AC1F58D0FD402CF8FE4C44444546EEDE4144F03CA8434B44E8FA444444444418414A43441F47AC1F1041CA44414444FD1C114B1A10424747485A86";
		String decryptedMsg1 = "0300407C403E0000A122011B09B21A5634A304C2A6AE020000050DEE3E0100A482B6080700E6AB000000000016010B08001A09B21A14012B00010000A31211071B140C090906";
		String encryptedMsg2 = "0F0187140194B93A13D0939974B2B93C127D92F94704B1490C289499129B76B91C3E999499444444381FB49999999999B9999980999995F6B699B99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999BFA5";
		String decryptedMsg2 = "01809C29450900A18D80932DA40DB01A51821053D701002D08AE80239F000100111111972B81000000000080000075000006BE8E00800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

		Decrypter decrypter = new Decrypter();
		try{
			String result1 = decrypter.decryptTest(encryptedMsg1);
			String result2 = decrypter.decryptTest(encryptedMsg2);
			assertEquals(decryptedMsg1, result1);
			assertEquals(decryptedMsg2, result2);
		}
		catch(Exception e)
		{
			System.out.print(e.toString());
			assertNull(e);
		}
		
		
	}
	
}
