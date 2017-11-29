package commonldap.commonldap;

import java.util.*;
import commonldap.commonldap.JCaData;

public class JCaContainer {
	private List<Object> lObj;
	
	public JCaContainer() {
		lObj = new ArrayList<Object>();
	}
	
	public void clear() {
		ListIterator<Object> lIter = lObj.listIterator();
		while (lIter.hasNext()) {
			JCaData lKey = (JCaData)lIter.next();
			lKey.clear();
		}
		
		lObj.clear();
	}
	
	public int getKeyCount() {
		return lObj.size();
	}
	
	public int getKeyElementCount(String sKey) {
		boolean bFound = false;
		int nCount = 0;
		ListIterator<Object> lIter = lObj.listIterator();
		while (lIter.hasNext() && !bFound) {
			JCaData lKey = (JCaData)lIter.next();
			if (sKey.contentEquals(lKey.getKey()) ) {
				bFound = true;
				nCount = lKey.getCount();	
			}
		}
		
		return nCount;
	}
	
	public String[] getKeyList() {
		String[] lStrings = new String[lObj.size()];
		ListIterator<Object> lIter = lObj.listIterator();
		int i=0;
		
		while (lIter.hasNext()) {
			JCaData lKey = (JCaData)lIter.next();
			lStrings[i++] = lKey.getKey();
		}
		
		return lStrings;
	}
	
	public boolean isEmpty() {
		return (lObj.size() == 0);
	}
	
	public boolean isKeyExist(String sKey) {
		ListIterator<Object> lIter = lObj.listIterator();
		while (lIter.hasNext()) {
			JCaData lKey = (JCaData)lIter.next();
			if (sKey.contentEquals(lKey.getKey()) )
				return true;
		}
		
		return false;		
	}
	
	public void setInt(String sKey, int iValue, int iIndex) {
		ListIterator<Object> lIter = lObj.listIterator();
		while (lIter.hasNext()) {
			JCaData lKey = (JCaData)lIter.next();
			if (sKey.contentEquals(lKey.getKey()) ) {
				lKey.setInt(iValue, iIndex);
				return;
			}
		}
		JCaData lKey = new JCaData(sKey,1);
		lKey.setInt(iValue, iIndex);
		lObj.add((Object)lKey);
	}
	
	public int getInt(String sKey, int iIndex) {
		ListIterator<Object> lIter = lObj.listIterator();
		while (lIter.hasNext()) {
			JCaData lKey = (JCaData)lIter.next();
			if (sKey.contentEquals(lKey.getKey()) ) {
				return lKey.getInt(iIndex);
			}
		}		
		return 0; //throw exception?
	}

	public void setString(String sKey, String sValue, int iIndex) {
		ListIterator<Object> lIter = lObj.listIterator();
		while (lIter.hasNext()) {
			JCaData lKey = (JCaData)lIter.next();
			if (sKey.contentEquals(lKey.getKey()) ) {
				lKey.setString(sValue, iIndex);
				return;
			}
		}
		JCaData lKey = new JCaData(sKey,2);
		lKey.setString(sValue, iIndex);
		lObj.add((Object)lKey);
	}
	
	public String getString(String sKey, int iIndex) {
		ListIterator<Object> lIter = lObj.listIterator();
		while (lIter.hasNext()) {
			JCaData lKey = (JCaData)lIter.next();
			if (sKey.contentEquals(lKey.getKey()) ) {
				return lKey.getString(iIndex);
			}
		}		
		return ""; //throw exception?
	}

	public int[] find(String sKey, String sValue) {
		ListIterator<Object> lIter = lObj.listIterator();
		while (lIter.hasNext()) {
			JCaData lKey = (JCaData)lIter.next();
			if (sKey.contentEquals(lKey.getKey()) ) {
				return lKey.findString(sValue);
			}
		}		
		
		return new int[0];
	}
	
	public int[] find(String sKey, int iValue) {
		ListIterator<Object> lIter = lObj.listIterator();
		while (lIter.hasNext()) {
			JCaData lKey = (JCaData)lIter.next();
			if (sKey.contentEquals(lKey.getKey()) ) {
				return lKey.findInt(iValue);
			}
		}		
		
		return new int[0];
	}
}
