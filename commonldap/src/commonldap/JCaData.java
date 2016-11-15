package commonldap;

import java.util.*;

public class JCaData {
	private int iType;
	private String sKey;
	private List<Object> lObj;
	
	public JCaData(String sNewKey, int iNewType) {
		this.iType = iNewType;
		this.sKey = sNewKey;
		this.lObj = new ArrayList<Object>();
	}
	
	public void clear() {
		this.lObj.clear();
		this.iType = 0;
		this.sKey = "";
	}
	
	public int getCount() {
		return this.lObj.size();
	}
	
	public void setType(int iType) {
		this.iType = iType;
	}
	
	public int getType() {
		return this.iType;
	}
	
	public void setKey(String sKey) {
		this.sKey = sKey;
	}
	
	public String getKey() {
		return this.sKey;
	}
	
	public void setInt(int iValue, int iIndex) {
		if (iIndex >= this.getCount() ) {
			this.lObj.add(iIndex,iValue);
		}
		else {
			this.lObj.set(iIndex, iValue);
		}
	}
	
	public void setString(String sValue, int iIndex) {
		if (iIndex >= this.getCount() ) {
			this.lObj.add(sValue);
		}
		else {
			this.lObj.set(iIndex, sValue);
		}		
	}
	
	public int getInt(int iIndex) {
		if (iIndex >= this.getCount())
			return 0;
		else
			return (int)this.lObj.get(iIndex);
	}
	
	public String getString(int iIndex)  {
		if (iIndex >= this.getCount())
			return "";
		else
			return (String)this.lObj.get(iIndex);		
	}

	public int[] findString(String sValue) {
		List<Object> lFound = new ArrayList<Object>();

		for (int iIndex=0; iIndex<this.getCount(); iIndex++) {
			if (this.getString(iIndex).contentEquals(sValue)) {
				lFound.add(iIndex);
			}
		}
		
		int[] aReturn = new int[lFound.size()];
		for (int i=0; i<lFound.size(); i++) {
			aReturn[i] = (int)lFound.get(i);
		}
		
		lFound.clear();
		return aReturn;
	}
	
	public int[] findInt(int iValue) {
		List<Object> lFound = new ArrayList<Object>();

		for (int iIndex=0; iIndex<this.getCount(); iIndex++) {
			if (this.getInt(iIndex) == iValue) {
				lFound.add(iIndex);
			}
		}
		
		int[] aReturn = new int[lFound.size()];
		for (int i=0; i<lFound.size(); i++) {
			aReturn[i] = (int)lFound.get(i);
		}
		
		lFound.clear();
		return aReturn;	
	}
}

