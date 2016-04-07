/*
 * Copyright (c) 2017, eramde
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package tk.sot_tech.oidm.datasource;

import Thor.API.Exceptions.tcAPIException;
import Thor.API.Exceptions.tcColumnNotFoundException;
import Thor.API.Exceptions.tcInvalidLookupException;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Map.Entry;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import javax.naming.ldap.*;
import javax.xml.bind.DatatypeConverter;
import tk.sot_tech.oidm.sch.AbstractDataSource;
import tk.sot_tech.oidm.sch.SheduledTaskTerminatedException;
import tk.sot_tech.oidm.sch.processor.LookupProcessor;
import tk.sot_tech.oidm.utility.LookupUtility;
import tk.sot_tech.oidm.utility.Misc;

public class ADDataSource extends AbstractDataSource {

	private static final ResourceBundle BUNDLE = ResourceBundle.getBundle("resources/ldaprecon");

	public static final String RECON_OBJECT_PARAMETER = BUNDLE.getString("recon.object"),
			RECON_PAGE_SIZE = BUNDLE.getString("lookup.config.page"),
			CONFIG_LOOKUP_MASK = BUNDLE.getString("lookup.config.mask"),
			OBJECT_ATTRIBUTE_LOOKUP = BUNDLE.getString("lookup.attributes"),
			OBJECT_MULTIVAL_LOOKUP = BUNDLE.getString("lookup.attributes.multival"),
			OBJECT_ADDITIONAL_FILTER = BUNDLE.getString("lookup.attributes.filter"),
			OBJECT_KEY = BUNDLE.getString("lookup.attributes.key"),
			CONFIG_SEARCH_SUBDOMAINS = BUNDLE.getString("lookup.config.subdomains"),
			CONFIG_SEARCH_BASE = BUNDLE.getString("lookup.config.container"),
			DNS_PREFIX = "dns:/_ldap._tcp.ForestDnsZones.",
			LDAP_ZERO_TIMESTAMP = "19900101000000.0Z",
			LDAP_SIMPLE_REQUEST_MASK = "(&(objectClass=%s)%s)",
			LDAP_CHANGED_REQUEST_MASK = "(&(objectClass=%s)(whenChanged>=%s)%s)",
			LOOKUP_FLAG = "[LOOKUP]";
	public static final String[] SRV = new String[]{"SRV"}, BINARY_ATTRS = BUNDLE.getString(
			"lookup.attributes.binary").split(";");
	private String objectKeyField, objectType, additionalFilter;
	private final HashMap<String, String> reconFieldMap = new HashMap<>(),
			reconMultivalueFieldMap = new HashMap<>();
	private ArrayList<String> searchBases;
	public static final SimpleDateFormat LDAP_TIMESTAMP = new SimpleDateFormat("yyyyMMddhhmmss.0'Z'");
	private int pageSize = 500;
	private boolean searchChildDomains = false, useSsl = false;
	private static final Logger LOG = Logger.getLogger(ADDataSource.class.getName());

	@Override
	protected AbstractDataSource initImpl() {
		HashMap<String, String> baseConfiguration = new HashMap<>(),
				objectConfiguration = new HashMap<>();
		String configLookup = parameters.getItParameters().get(BUNDLE.getString("itresource.configLookup"));
		LookupUtility lku = new LookupUtility();
		try {
			baseConfiguration.putAll(lku.getLookup(configLookup));
			objectType = parameters.getParameters().get(RECON_OBJECT_PARAMETER);
			if (Misc.isNullOrEmpty(objectType)) {
				throw new IllegalStateException(
						RECON_OBJECT_PARAMETER + " parameter not set. Append field 'Additional parameters' with object name like '...,"
						+ RECON_OBJECT_PARAMETER + "=User'");
			}
			searchChildDomains = "YES".equalsIgnoreCase(baseConfiguration.get(
					CONFIG_SEARCH_SUBDOMAINS));
			useSsl = "YES".equalsIgnoreCase(parameters.getItParameters().get(BUNDLE.getString("lookup.config.ssl")));
			String searchDomain;
			if (baseConfiguration.containsKey(RECON_PAGE_SIZE)) {
				pageSize = Integer.decode(baseConfiguration.get(RECON_PAGE_SIZE));
			}
			String objectLookup = baseConfiguration.get(
					String.format(CONFIG_LOOKUP_MASK, objectType));
			if (Misc.isNullOrEmpty(objectLookup)) {
				throw new IllegalStateException(
						"Configuration Lookup for object " + objectType + " not set in " + configLookup);
			}
			objectConfiguration.putAll(lku.getLookup(objectLookup));
			objectKeyField = objectConfiguration.get(OBJECT_KEY);
			if (Misc.isNullOrEmpty(objectKeyField)) {
				throw new IllegalStateException(OBJECT_KEY + " not set in " + objectLookup);
			}
			String mapLookup = objectConfiguration.get(OBJECT_ATTRIBUTE_LOOKUP);
			if (Misc.isNullOrEmpty(mapLookup)) {
				throw new IllegalStateException(
						OBJECT_ATTRIBUTE_LOOKUP + " not set in " + objectLookup);
			}
			HashMap<String, String> mapping = lku.getLookup(mapLookup), remapping = new HashMap<>();
			int i = 0;
			String tmp;
			while (BUNDLE.containsKey("remap." + i)) {
				tmp = BUNDLE.getString("remap." + i++);
				if (!Misc.isNullOrEmpty(tmp)) {
					String[] remap = tmp.split(":");
					remapping.put(remap[0], remap[1]);
				}
			}
			for (Entry<String, String> entry : mapping.entrySet()) {
				String value = entry.getValue();
				if (remapping.containsKey(value)) {
					value = remapping.get(value);
				}
				if (!"!IGNORE!".equalsIgnoreCase(value)) {
					reconFieldMap.put(entry.getKey(), value);
				}
			}
			mapLookup = objectConfiguration.get(OBJECT_MULTIVAL_LOOKUP);
			if (Misc.isNullOrEmpty(mapLookup)) {
				LOG.log(Level.WARNING, "{0} not set in {1}", new Object[]{OBJECT_MULTIVAL_LOOKUP,
																		  objectLookup});
			}
			else {
				reconMultivalueFieldMap.putAll(lku.getLookup(mapLookup));
			}
			additionalFilter = objectConfiguration.containsKey(OBJECT_ADDITIONAL_FILTER)
							   ? objectConfiguration.get(OBJECT_ADDITIONAL_FILTER)
							   : "";

			if (objectConfiguration.containsKey(CONFIG_SEARCH_BASE)) {
				LOG.log(Level.INFO, "{0} set in {1}, search in subdomains is disabled",
						new Object[]{CONFIG_SEARCH_BASE, objectLookup});
				searchDomain = objectConfiguration.get(CONFIG_SEARCH_BASE);
				searchChildDomains = false;
			}
			else {
				searchDomain = parameters.getItParameters().get(BUNDLE.getString("itresource.domain"));
			}
			searchBases = getSearchBases(searchChildDomains, searchDomain);
			LOG.log(Level.INFO, "\nSearch Domains {0}\n"
								   + "Key Field {1}\n"
								   + "Object Type {2}\n"
								   + "Additional Filter {3}\n"
								   + "Recon Field Map {4}\n"
								   + "Multivalue Map {5}\n"
								   + "Use SSL {6}\n", new Object[]{searchBases,
																   objectKeyField,
																   objectType,
																   additionalFilter,
																   reconFieldMap,
																   reconMultivalueFieldMap,
																   useSsl});
		}
		catch (NamingException | tcAPIException | tcInvalidLookupException | tcColumnNotFoundException | 
				SheduledTaskTerminatedException ex) {
			Logger.getLogger(ADDataSource.class.getName()).severe(Misc.ownStack(ex));
			throw new IllegalStateException(ex);
		}
		return this;
	}

	@Override
	public ArrayList<HashMap<String, Object>> fetchData() throws Exception,
																 SheduledTaskTerminatedException {
		ArrayList<HashMap<String, Object>> result = new ArrayList<>();
		if (parameters.getParameters().containsKey(LookupProcessor.LOOKUP_KEY)) {
			String request = String.format(LDAP_SIMPLE_REQUEST_MASK, objectType, additionalFilter);
			result = getObjectData(request, objectType, reconFieldMap);
		}
		else {
			ArrayList<String> updatedIds = getUpdatedIds(), proceedIds = new ArrayList<>(updatedIds.
					size() / 2);
			if (!Misc.isNullOrEmpty(updatedIds)) {
				for (String search : updatedIds) {
					ArrayList<HashMap<String, Object>> mainDataList = getObjectData(search,
																					objectType,
																					reconFieldMap);
					for (HashMap<String, Object> mainData : mainDataList) {
						String objectKey = (String) mainData.get(objectKeyField);
						if (!proceedIds.contains(objectKey)) {
							HashMap<String, ArrayList<HashMap<String, Object>>> secondaryData = getSecondaryObjectsData(
									mainData);
							if (!Misc.isNullOrEmpty(secondaryData)) {
								mainData.put(MULTIVALUED_KEY, secondaryData);
							}
							proceedIds.add(objectKey);
							result.add(mainData);
						}
					}
				}
			}
		}
		return result;
	}

	private ArrayList<String> getUpdatedIds() throws NamingException,
													 SheduledTaskTerminatedException {
		ArrayList<String> result = new ArrayList<>();
		String request, timeStamp = LDAP_ZERO_TIMESTAMP;
		if (parameters.getFromDate() != null && parameters.getFromDate().getTime() != new Date(0).
				getTime()) {
			timeStamp = LDAP_TIMESTAMP.format(parameters.getFromDate());
		}
		request = String.format(LDAP_CHANGED_REQUEST_MASK, objectType, timeStamp, additionalFilter);
		SearchControls mainObjectSearchControls = new SearchControls();
		HashMap<String, String> secondaryObjects = new HashMap<>(reconMultivalueFieldMap.size());
		mainObjectSearchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		mainObjectSearchControls.setReturningAttributes(new String[]{objectKeyField});

		for (String key : reconMultivalueFieldMap.keySet()) {
			String[] tmp = key.split("\\:.*\\~");
			if (tmp != null && tmp.length >= 2) {
				secondaryObjects.put(tmp[0], tmp[1]);
			}
		}
		for (String domain : searchBases) {
			LdapContext context = null;
			ArrayList<Attributes> ldapResult = new ArrayList<>();
			try {
				context = connect(domain);
				ldapResult = performSearch(context, domain, request,
										   mainObjectSearchControls);
			}
			finally {
				if (context != null) {
					context.close();
				}
			}
			for (Attributes records : ldapResult) {
				task.isTerminated();
				if (records != null) {
					Attribute attribute = records.get(objectKeyField);
					String data = convertToSearchString(attribute.get(), attribute.getID());
					result.add(data);
				}
			}
		}
		int len = result.size();
		LOG.log(Level.INFO, "GOT {0} UPDATED VALUES OF MAIN OBJECT", len);
		for (Entry<String, String> secondaryObject : secondaryObjects.entrySet()) {
			String[] tmp = secondaryObject.getValue().split("=");
			String fieldToReturn = tmp[0], mainObjectLinkField = tmp[1];
			SearchControls secondaryObjectSearchControls = new SearchControls();
			secondaryObjectSearchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
			secondaryObjectSearchControls.setReturningAttributes(new String[]{fieldToReturn});
			request = String.format(LDAP_CHANGED_REQUEST_MASK, secondaryObject.getKey(), timeStamp,
									"");
			for (String domain : searchBases) {
				LdapContext context = null;
				ArrayList<Attributes> ldapResult = new ArrayList<>();
				try {
					context = connect(domain);
					ldapResult = performSearch(context, domain, request,
											   secondaryObjectSearchControls);
				}
				finally {
					if (context != null) {
						context.close();
					}
				}

				if (ldapResult != null) {
					for (Attributes records : ldapResult) {
						task.isTerminated();
						if (records != null) {
							Attribute attribute = records.get(fieldToReturn);
							if (attribute != null) {
								NamingEnumeration<?> allValues = records.get(fieldToReturn).getAll();
								while (allValues.hasMoreElements()) {
									task.isTerminated();
									result.add(convertToSearchString(allValues.nextElement(),
																	 mainObjectLinkField));
								}
							}
						}
					}
				}
			}
			LOG.log(Level.INFO, "GOT {0} UPDATED VALUES FROM SECONDARY OBJECT {1}", new Object[]{
				result.size() - len, secondaryObject.getKey()});
			len = result.size();
		}
		LOG.log(Level.INFO, "TOTAL UPDATED OBJECTS {0}", result.size());
		return result;
	}

	private Object convertLdapAttributeToObject(Object data, String type) {
		if (Misc.equalsAny(type, BINARY_ATTRS, true) && data != null && data instanceof byte[]) {
			data = DatatypeConverter.printHexBinary(((byte[]) data)).toLowerCase();
		}
		return data;
	}

	private String convertToSearchString(Object data, String type) {
		data = convertLdapAttributeToObject(data, type);
		if (Misc.equalsAny(type, BINARY_ATTRS, true) && data != null) {
			String tmp = (String) data;
			StringBuilder sb = new StringBuilder();
			int i = 0;
			while (i < tmp.length()) {
				int start = i;
				int end = i += 2;
				sb.append('\\').append(tmp.substring(start, end));
			}
			data = sb.toString();
		}
		else {
			data = String.valueOf(data);
		}
		return "(" + type + '=' + data + ')';
	}

	private LdapContext connect(String base) throws NamingException {
		Properties env = new Properties();
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.REFERRAL, "follow");
		String tmp = parameters.getItParameters().get(BUNDLE.getString("itresource.port"));
		env.put(Context.PROVIDER_URL,
				(useSsl ? "ldaps://" : "ldap://") + (searchChildDomains ? convertDistinguisahedNameToDomainName(
													 base) : parameters.getItParameters().get(BUNDLE.
													 getString(
													 "itresource.host")))
				+ ':' + (Misc.isNullOrEmpty(tmp) ? (useSsl ? "636" : "389") : tmp) + '/');
		env.put(Context.SECURITY_AUTHENTICATION, "simple");

		env.put(Context.SECURITY_PRINCIPAL, parameters.getItParameters().get(BUNDLE.getString("itresource.user")));
		env.put(Context.SECURITY_CREDENTIALS, parameters.getItParameters().get(BUNDLE.getString(
				"itresource.password")));
		StringBuilder sb = new StringBuilder();
		for (String s : BINARY_ATTRS) {
			sb.append(s).append(' ');
		}
		sb.deleteCharAt(sb.length() - 1);
		env.put("java.naming.ldap.attributes.binary", sb.toString());
		return new InitialLdapContext(env, null);
	}

	private ArrayList<Attributes> performSearch(LdapContext context, String base, String request,
												SearchControls searchControls) throws
			SheduledTaskTerminatedException {
		ArrayList<Attributes> result = new ArrayList<>();
		LdapContext contextLoc = null;
		try {
			byte[] cookie = null;
			contextLoc = context.newInstance(null);
			contextLoc.setRequestControls(new Control[]{
				new PagedResultsControl(pageSize, Control.CRITICAL)
			});
			do {
				NamingEnumeration<SearchResult> searchResults = contextLoc.search(base, request,
																				  searchControls);
				while (searchResults != null && searchResults.hasMoreElements()) {
					task.isTerminated();
					SearchResult searchResult = searchResults.nextElement();
					Attributes attributes = searchResult.getAttributes();
					result.add(attributes);
				}
				Control[] controls = contextLoc.getResponseControls();
				if (controls != null) {
					for (Control control : controls) {
						if (control instanceof PagedResultsResponseControl) {
							PagedResultsResponseControl prrc = (PagedResultsResponseControl) control;
							cookie = prrc.getCookie();
						}
					}
				}
				else {
					LOG.warning("No controls were sent from the server");
				}
				contextLoc.setRequestControls(new Control[]{
					new PagedResultsControl(pageSize, cookie, Control.CRITICAL)});
			}
			while (cookie != null);
		}
		catch (NamingException | IOException ex) {
			Logger.getLogger(ADDataSource.class.getName()).severe(Misc.ownStack(ex));
		}
		finally {
			if (contextLoc != null) {
				try {
					contextLoc.close();
				}
				catch (NamingException ex) {
					Logger.getLogger(ADDataSource.class.getName()).severe(Misc.ownStack(ex));
				}
			}
		}
		return result;
	}

	public ArrayList<String> convertDomainNamesToDistinguishedNames(ArrayList<String> domains) {
		ArrayList<String> dn = new ArrayList<>(domains.size());
		for (String domain : domains) {
			if (!Misc.isNullOrEmpty(domain)) {
				if (domain.contains("=")) {
					dn.add(domain);
				}
				else {
					dn.add("dc=" + domain.replace(".", ",dc="));
				}
			}
		}
		return dn;
	}

	private String convertDistinguisahedNameToDomainName(String base) {
		return base.replace("dc=", "").replace(',', '.');
	}

	public ArrayList<String> getSearchBases(boolean searchChildDomains, String searchDomain) throws
			NamingException, SheduledTaskTerminatedException {
		ArrayList<String> domains;
		if (searchChildDomains) {
			domains = findSubDomainsFromDns(searchDomain);
		}
		else {
			domains = new ArrayList<>(1);
			domains.add(searchDomain);
		}
		domains = convertDomainNamesToDistinguishedNames(domains);
		return domains;
	}

	public ArrayList<String> findSubDomainsFromDns(String name)
			throws NamingException, SheduledTaskTerminatedException {
		ArrayList<String> result = new ArrayList<>();
		DirContext ctx = new InitialDirContext();

		Attributes attrs = ctx.getAttributes(DNS_PREFIX + name, SRV);
		if (attrs.get("SRV") == null) {
			return result;
		}

		NamingEnumeration<?> e = attrs.get("SRV").getAll();

		while (e.hasMoreElements()) {
			task.isTerminated();
			String line = (String) e.nextElement();

			String[] parts = line.split("\\s+");
			String host = parts[3];
			host = host.substring(host.indexOf('.') + 1, host.lastIndexOf('.'));
			if (!Misc.isNullOrEmpty(host)) {
				host = host.toLowerCase();
				if (!result.contains(host)) {
					result.add(host);
				}
			}

		}

		return result;
	}

	private ArrayList<HashMap<String, Object>> getObjectData(String search, String objectClass,
															 HashMap<String, String> returnFieldsMap)
			throws SheduledTaskTerminatedException,
				   NamingException {
		ArrayList<HashMap<String, Object>> result = new ArrayList<>();

		String request = String.format(LDAP_SIMPLE_REQUEST_MASK, objectClass, search);
		SearchControls searchControls = new SearchControls();
		String[] returnAttributes = returnFieldsMap.values().toArray(new String[returnFieldsMap.
				size()]);
		searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		searchControls.setReturningAttributes(returnAttributes);
		for (String domain : searchBases) {
			LOG.log(Level.INFO, "SEARCH BASE {0} REQUEST {1} RETURN {2}", new Object[]{domain,
																					   request,
																					   Arrays.
																					   toString(
																					   searchControls.
																					   getReturningAttributes())});
			LdapContext context = null;
			ArrayList<Attributes> ldapResult = new ArrayList<>();
			try {
				context = connect(domain);
				ldapResult = performSearch(context, domain, request,
										   searchControls);
			}
			finally {
				if (context != null) {
					context.close();
				}
			}
			for (Attributes records : ldapResult) {
				HashMap<String, Object> recordResult = new HashMap<>();
				task.isTerminated();
				if (records != null) {
					NamingEnumeration<? extends Attribute> recordAttributes = records.getAll();
					while (recordAttributes.hasMoreElements()) {
						task.isTerminated();
						Attribute attribute = recordAttributes.next();
						String name = attribute.getID();
						Object data = convertLdapAttributeToObject(attribute.get(), name);
						if (objectKeyField.equalsIgnoreCase(name)) {
							recordResult.put(objectKeyField, data);
						}
						for (Entry<String, String> entry : returnFieldsMap.entrySet()) {
							task.isTerminated();
							if (name.equalsIgnoreCase(entry.getValue())) {
								String putName = entry.getKey();
								if (putName.contains(LOOKUP_FLAG) && includeItResource && data instanceof String) {
									data = String.format("%d~%s", itKey, (String) data);
									putName = putName.replace(LOOKUP_FLAG, "");
								}
								recordResult.put(putName, data);
							}
						}
					}
					boolean hasAgregations = false;
					HashMap<String, ArrayList<String>> valuesByGroup = new HashMap<>();
					for (String name : recordResult.keySet()) {
						if (name.indexOf('{') >= 0) {
							hasAgregations = true;
							String group = name.substring(name.indexOf('{') + 1, name.indexOf(':'));
							int index = Integer.decode(name.substring(name.indexOf(':') + 1, name.
																	  indexOf('}')));
							ArrayList<String> values = valuesByGroup.get(group);
							if (values == null) {
								values = new ArrayList<>();
								valuesByGroup.put(group, values);
							}
							values.ensureCapacity(index + 1);
							values.add(index, (String) recordResult.get(name));
						}
					}
					if (hasAgregations) {
						HashMap<String, String> groupValues = new HashMap<>();
						for (String group : valuesByGroup.keySet()) {
							StringBuilder sb = new StringBuilder();
							for (String value : valuesByGroup.get(group)) {
								if(!Misc.isNullOrEmpty(value)){
									sb.append(value).append("; ");
								}
							}
							if(sb.lastIndexOf("; ") == sb.length() - 2){
								sb.deleteCharAt(sb.length() - 2);
							}
							groupValues.put(group, sb.toString());
						}
						for (String group : groupValues.keySet()) {
							String value = groupValues.get(group);
							ArrayList<String> keys = new ArrayList<>(recordResult.keySet());
							for (String name : keys) {
								String groupSearch = "{" + group + ':';
								if (name.contains(groupSearch)) {
									String newName = name.replaceAll("\\{[a-zA-Z0-9 ]*:[0-9]*\\}",
																	 "");
									recordResult.remove(name);
									recordResult.put(newName, value);
								}
							}
						}
					}
					result.add(recordResult);
				}
			}
		}
		return result;
	}

	private HashMap<String, ArrayList<HashMap<String, Object>>> getSecondaryObjectsData(
			HashMap<String, Object> mainData) throws SheduledTaskTerminatedException,
													 NamingException {
		HashMap<String, ArrayList<HashMap<String, Object>>> result = new HashMap<>();
		HashMap<String, HashMap<String, String>> returnFieldsByObject = new HashMap<>();
		HashMap<String, String> searchRequestByObject = new HashMap<>(), childTablesRemap = new HashMap<>();
		final String splitRegexp = "~|:|=";
		for (Entry<String, String> entry : reconMultivalueFieldMap.entrySet()) {
			task.isTerminated();
			String[] codeValues = entry.getKey().split(splitRegexp), decodeValues = entry.getValue().
					split("~");
			if (codeValues.length < 4) {
				throw new IllegalArgumentException("Invalid Multivalue Lookup Code Value: " + entry.
						getKey());
			}
			if (decodeValues.length < 2) {
				throw new IllegalArgumentException(
						"Invalid Multivalue Lookup Decode Value: " + entry.getValue());
			}
			String objectClass = codeValues[0],
					returnField = codeValues[1],
					searchField = codeValues[2],
					mainObjectSearchField = codeValues[3],
					returnTableRemap = decodeValues[0],
					returnFieldRemap = decodeValues[1];
			HashMap<String, String> returnFieldsRemap = returnFieldsByObject.get(objectClass);
			if (returnFieldsRemap == null) {
				returnFieldsRemap = new HashMap<>();
				returnFieldsByObject.put(objectClass, returnFieldsRemap);
			}
			returnFieldsRemap.put(returnFieldRemap, returnField);
			if (!childTablesRemap.containsKey(objectClass)) {
				childTablesRemap.put(objectClass, returnTableRemap);
			}
			if (!searchRequestByObject.containsKey(objectClass)) {
				String searchRequest = convertToSearchString(mainData.get(
						remapLdapAttributeNameToReturned(mainObjectSearchField)),
															 searchField);
				searchRequestByObject.put(objectClass, searchRequest);
			}
		}
		for (String searchObject : searchRequestByObject.keySet()) {
			task.isTerminated();
			ArrayList<HashMap<String, Object>> objectData = getObjectData(searchRequestByObject.get(
					searchObject),
																		  searchObject,
																		  returnFieldsByObject.get(
																				  searchObject));
			result.put(childTablesRemap.get(searchObject), objectData);
		}
		return result;
	}

	public String remapLdapAttributeNameToReturned(String ldapName) {
		for (Entry<String, String> entry : reconFieldMap.entrySet()) {
			if (entry.getValue().equalsIgnoreCase(ldapName)) {
				return entry.getKey();
			}
		}
		return null;
	}

	@Override
	public void clearData(ArrayList<HashMap<String, Object>> values) throws Exception,
																			SheduledTaskTerminatedException {

	}

	@Override
	public void close() throws Exception {

	}

}
