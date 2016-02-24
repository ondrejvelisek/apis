package org.surfnet.oaaas.authentication;

/**
 * @author Michal Prochazka <michalp@ics.muni.cz>
 *
 */
public interface ExtSourcesManager {

	public static final String EXTSOURCE_IDP = "cz.metacentrum.perun.core.impl.ExtSourceIdp";
	public static final String EXTSOURCE_SQL = "cz.metacentrum.perun.core.impl.ExtSourceSql";
	public static final String EXTSOURCE_LDAP = "cz.metacentrum.perun.core.impl.ExtSourceLdap";
	public static final String EXTSOURCE_KERBEROS = "cz.metacentrum.perun.core.impl.ExtSourceKerberos";
	public static final String EXTSOURCE_INTERNAL = "cz.metacentrum.perun.core.impl.ExtSourceInternal";
	public static final String EXTSOURCE_ISMU = "cz.metacentrum.perun.core.impl.ExtSourceISMU";
	public static final String EXTSOURCE_X509 = "cz.metacentrum.perun.core.impl.ExtSourceX509";

	/**
	 * Name of the LOCAL extSource, which is used for users without any external authentication.
	 * extLogin is generated on the fly, usually it is time of the first access.
	 */
	public static final String EXTSOURCE_NAME_LOCAL = "LOCAL";

	/**
	 * Name of the INTERNAL extSource, which is used for internal Perun components like Registrar etc.
	 */
	public static final String EXTSOURCE_NAME_INTERNAL = "INTERNAL";

	/**
	 * Name of the default extSource which have every user in Perun.
	 */
	public static final String EXTSOURCE_NAME_PERUN = "PERUN";
}
