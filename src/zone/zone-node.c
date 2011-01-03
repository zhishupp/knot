#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

#include <ldns/ldns.h>

#include "zone-node.h"
#include "common.h"
#include "skip-list.h"

/*----------------------------------------------------------------------------*/

#define RFRS(arr) ((const zn_node_t **)da_get_items(arr))
#define RFRS_COUNT(arr) (da_get_count(arr))

/*----------------------------------------------------------------------------*/

static const uint RRSETS_COUNT = 10;

/*! \brief Zone node flags. */
enum zn_flags {
	/*! \brief Xxxxxxxx1 - node is delegation point (ref.glues is set) */
	FLAGS_DELEG = 0x1,

	/*!
	 * \brief Xxxxxxx1x - node is non-authoritative (carrying only glue
	 *        records)
	 */
	FLAGS_NONAUTH = 0x2,

	/*! \brief Xxxxxx1xx - node carries a CNAME record (ref.cname is set) */
	FLAGS_HAS_CNAME = 0x4,

	/*!
	 * \brief Xxxxx1xxx - node carries an MX record (ref.additional is set)
	 */
	FLAGS_HAS_MX = 0x8,
	/*!
	 * \brief Xxxx1xxxx - node carries an NS record (ref.additional is set)
	 */
	FLAGS_HAS_NS = 0x10,
	/*!
	 * \brief Xxx1xxxxx - node carries a SRV record (ref.additional is set)
	 */
	FLAGS_HAS_SRV = 0x20,
	/*!
	 * \brief Xx1xxxxxx - node is referenced by some CNAME record (referrer
	 *        is set)
	 */
	FLAGS_REF_CNAME = 0x40,
	/*!
	 * \brief X1xxxxxxx - node is referenced by some MX record (referrer is
	 *        set)
	 */
	FLAGS_REF_MX = 0x80,

	/*!
	 * \brief xxxxxxx1X - node is referenced by some NS record (referrer is
	 *        set)
	 */
	FLAGS_REF_NS = 0x100,

	/*!
	 * \brief xxxxxx1xX - node is referenced by some SRV record (referrer
	 *        is set)
	 */
	FLAGS_REF_SRV = 0x200
};

typedef enum zn_flags zn_flags_t;

/*----------------------------------------------------------------------------*/
/* Private functions                                                          */
/*----------------------------------------------------------------------------*/

static zn_ar_rrsets_t *zn_create_ar_rrsets()
{
	zn_ar_rrsets_t *ar = malloc(sizeof(zn_ar_rrsets_t));
	if (ar == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}
	ar->a = NULL;
	ar->aaaa = NULL;
	ar->cname = NULL;

	return ar;
}

/*----------------------------------------------------------------------------*/

static void zn_destroy_ar_rrsets(zn_ar_rrsets_t **ar)
{
	free(*ar);
}

/*----------------------------------------------------------------------------*/

static void zn_dtor_ar_rrsets(void *value)
{
	zn_ar_rrsets_t *ar = (zn_ar_rrsets_t *)value;
	zn_destroy_ar_rrsets(&ar);
}

/*----------------------------------------------------------------------------*/

static zn_ar_rrsets_t *zn_create_ar_rrsets_for_ref(ldns_rr_list *ref_rrset)
{
	zn_ar_rrsets_t *ar = zn_create_ar_rrsets();

	switch (ldns_rr_list_type(ref_rrset)) {
	case LDNS_RR_TYPE_A:
		ar->a = ref_rrset;
		ar->aaaa = NULL;
		break;
	case LDNS_RR_TYPE_AAAA:
		ar->aaaa = ref_rrset;
		ar->a = NULL;
		break;
	default:
		free(ar);
		log_error("Error: trying to add MX record reference to a type "
		          "other than A or AAAA.\n");
		return NULL;
	}
	return ar;
}

/*----------------------------------------------------------------------------*/

static zn_ar_rrsets_t *zn_create_ar_rrsets_for_cname(const zn_node_t *node)
{
	zn_ar_rrsets_t *ar = zn_create_ar_rrsets();

	assert(ar->a == NULL);
	assert(ar->aaaa == NULL);
	ar->cname = node;

	return ar;
}

/*----------------------------------------------------------------------------*/

static int zn_compare_ar_keys(void *key1, void *key2)
{
	return ldns_dname_compare((ldns_rdf *)key1, (ldns_rdf *)key2);
}

/*----------------------------------------------------------------------------*/

static int zn_merge_ar_values(void **value1, void **value2)
{
	zn_ar_rrsets_t *ar1 = (zn_ar_rrsets_t *)(*value1);
	zn_ar_rrsets_t *ar2 = (zn_ar_rrsets_t *)(*value2);

	if ((ar2->a != NULL && ar1->a != NULL)
	    || (ar2->aaaa != NULL && ar1->aaaa != NULL)
	    || (ar2->cname != NULL && ar1->cname != NULL)) {
		return -1;
	}

	if (ar2->a != NULL) {
		ar1->a = ar2->a;
	} else if (ar2->aaaa != NULL) {
		ar1->aaaa = ar2->aaaa;
	} else if (ar2->cname != NULL) {
		ar1->cname = ar2->cname;
	}

	return 0;
}

/*----------------------------------------------------------------------------*/

static int zn_compare_keys(void *key1, void *key2)
{
	// in our case, key is of type ldns_rr_type, but as casting to enum may
	// result in undefined behaviour, we use regular unsigned int.
	return (key1 < key2) ? -1 : ((key1 > key2) ? 1 : 0);
}

/*----------------------------------------------------------------------------*/

static int zn_merge_values(void **value1, void **value2)
{
	if (ldns_rr_list_cat((ldns_rr_list *)(*value1),
	                     (ldns_rr_list *)(*value2))) {
		return 0;
	} else {
		return -1;
	}
}

/*----------------------------------------------------------------------------*/

static void zn_destroy_value(void *value)
{
	ldns_rr_list_deep_free((ldns_rr_list *)value);
}

/*----------------------------------------------------------------------------*/

static inline void zn_flags_set(uint16_t *flags, zn_flags_t flag)
{
	(*flags) |= flag;
}

/*----------------------------------------------------------------------------*/

static inline int zn_flags_get(uint16_t flags, zn_flags_t flag)
{
	return (flags & flag);
}

/*----------------------------------------------------------------------------*/

static inline int zn_flags_empty(uint16_t flags)
{
	return (flags == 0);
}

/*----------------------------------------------------------------------------*/

static int zn_add_referrer_node(zn_node_t *node, const zn_node_t *referrer)
{
	if (node->referrers == NULL) {
		node->referrers = da_create(1, sizeof(zn_node_t *));
		if (node->referrers == NULL) {
			log_error("%s(): Error while creating array.\n",
			          __func__);
			return -1;
		}
	}

	int res = da_reserve(node->referrers, 1);
	if (res < 0) {
		log_error("%s(): Error while reserving space.\n",
		          __func__);
		return -2;
	}

	RFRS(node->referrers)[RFRS_COUNT(node->referrers)] = referrer;
	res = da_occupy(node->referrers, 1);
	if (res != 0) {
		log_error("%s(): Error while occupying space.\n",
		          __func__);
		return -3;
	}

	return 0;
}

/*----------------------------------------------------------------------------*/

static int zn_has_additional(const zn_node_t *node)
{
	return (zn_has_mx(node) + zn_has_ns(node) + zn_has_srv(node));
}

/*----------------------------------------------------------------------------*/
/* Public functions                                                           */
/*----------------------------------------------------------------------------*/

zn_node_t *zn_create()
{
	zn_node_t *node = malloc(sizeof(zn_node_t));
	if (node == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	node->rrsets = skip_create_list(zn_compare_keys);
	if (node->rrsets == NULL) {
		free(node);
		return NULL;
	}

	node->next = NULL;
	node->prev = NULL;
	node->owner = NULL;
	// not a CNAME
	node->ref.cname = NULL;
	// not a delegation point
	node->flags = 0;
	// referenced by no node (do not initialize the array to save space)
	node->referrers = NULL;

	return node;
}

/*----------------------------------------------------------------------------*/

ldns_rdf *zn_owner(zn_node_t *node)
{
	return node->owner;
}

/*----------------------------------------------------------------------------*/

int zn_add_rr(zn_node_t *node, ldns_rr *rr)
{
	/*
	 * This whole function can be written with less code if we first create
	 * new rr_list, insert the RR into it and then call skip_insert and
	 * provide the merging function.
	 *
	 * However, in that case the allocation will occur always, what may be
	 * time-consuming, so we retain this version for now.
	 */
	if (rr == NULL) {
		return -7;
	}

	// accept only RR with the same owner
	if (node->owner
	    && ldns_dname_compare(node->owner, ldns_rr_owner(rr)) != 0) {
		return -6;
	}

	// find an appropriate RRSet for the RR
	ldns_rr_list *rrset = (ldns_rr_list *)skip_find(
			node->rrsets, (void *)ldns_rr_get_type(rr));

	// found proper RRSet, insert into it
	if (rrset != NULL) {
		assert(ldns_rr_list_type(rrset) == ldns_rr_get_type(rr));
		if (ldns_rr_list_push_rr(rrset, rr) != true) {
			return -3;
		}
	} else {
		rrset = ldns_rr_list_new();
		if (rrset == NULL) {
			ERR_ALLOC_FAILED;
			return -4;
		}
		// add the RR to the RRSet
		if (ldns_rr_list_push_rr(rrset, rr) != true) {
			return -5;
		}
		// insert the rrset into the node
		int res = skip_insert(node->rrsets,
		                      (void *)ldns_rr_get_type(rr),
		                      (void *)rrset, NULL);
		assert(res != 2 && res != -2);
		// if no owner yet and successfuly inserted
		if (node->owner == NULL && res == 0) {
			// set the owner
			node->owner = ldns_rdf_clone(ldns_rr_owner(rr));
		}
		return res;
	}

	return 0;
}

/*----------------------------------------------------------------------------*/

int zn_add_rrset(zn_node_t *node, ldns_rr_list *rrset)
{
	assert(ldns_is_rrset(rrset));
	// here we do not have to allocate anything even if the RRSet is not in
	// the list, so can use the shortcut (see comment in zn_add_rr()).
	int res = skip_insert(node->rrsets, (void *)ldns_rr_list_type(rrset),
	                      (void *)rrset, zn_merge_values);

	// if the node did not have any owner and insert successful, set owner
	if (node->owner == NULL && res == 0) {
		node->owner = ldns_rdf_clone(ldns_rr_list_owner(rrset));
	}

	return res;
}

/*----------------------------------------------------------------------------*/

ldns_rr_list *zn_find_rrset(const zn_node_t *node, ldns_rr_type type)
{
	ldns_rr_list *rrset = (ldns_rr_list *)skip_find(node->rrsets,
							(void *)type);
	debug_zn("Searching for type %d,%s in RRSets:\n", type,
	         ldns_rr_type2str(type));
	skip_print_list(node->rrsets, zn_print_rrset);

	assert(rrset == NULL || ldns_is_rrset(rrset));
	if (rrset != NULL) {
		debug_zn("Type demanded: %d,%s, type found: %d,%s\n", type,
		         ldns_rr_type2str(type), ldns_rr_list_type(rrset),
		         ldns_rr_type2str(ldns_rr_list_type(rrset)));
	}
	assert(rrset == NULL || ldns_rr_list_type(rrset) == type);

	return rrset;
}

/*----------------------------------------------------------------------------*/

ldns_rr_list *zn_all_rrsets(const zn_node_t *node)
{
	ldns_rr_list *all = ldns_rr_list_new();

	debug_zn("Extracting all RRSets from:\n");
	skip_print_list(node->rrsets, zn_print_rrset);

	const skip_node_t *sn = skip_first(node->rrsets);
	while (sn != NULL) {
		ldns_rr_list_push_rr_list(all, (ldns_rr_list *)sn->value);
		sn = skip_next(sn);
	}

	debug_zn("\nExtracted RRSets:\n%s\n", ldns_rr_list2str(all));
	return all;
}

/*----------------------------------------------------------------------------*/

int zn_is_empty(const zn_node_t *node)
{
	return (skip_is_empty(node->rrsets));
}

/*----------------------------------------------------------------------------*/

void zn_set_non_authoritative(zn_node_t *node)
{
	zn_flags_set(&node->flags, FLAGS_NONAUTH);
}

/*----------------------------------------------------------------------------*/

int zn_is_non_authoritative(const zn_node_t *node)
{
	return zn_flags_get(node->flags, FLAGS_NONAUTH);
}

/*----------------------------------------------------------------------------*/

void zn_set_delegation_point(zn_node_t *node)
{
	assert(node->ref.glues == NULL);
	node->ref.glues = ldns_rr_list_new();
	zn_flags_set(&node->flags, FLAGS_DELEG);
}

/*----------------------------------------------------------------------------*/

int zn_is_delegation_point(const zn_node_t *node)
{
	assert((zn_flags_get(node->flags, FLAGS_DELEG) == 0
	        || node->ref.glues != NULL));
	return zn_flags_get(node->flags, FLAGS_DELEG);
}

/*----------------------------------------------------------------------------*/

void zn_set_ref_cname(zn_node_t *node, zn_node_t *cname_ref)
{
	assert(node->ref.cname == NULL);
	node->ref.cname = cname_ref;
	zn_flags_set(&node->flags, FLAGS_HAS_CNAME);
}

/*----------------------------------------------------------------------------*/

int zn_has_cname(const zn_node_t *node)
{
	return zn_flags_get(node->flags, FLAGS_HAS_CNAME);
}

/*----------------------------------------------------------------------------*/

zn_node_t *zn_get_ref_cname(const zn_node_t *node)
{
	if (zn_flags_get(node->flags, FLAGS_HAS_CNAME) > 0) {
		return node->ref.cname;
	} else {
		return NULL;
	}
}

/*----------------------------------------------------------------------------*/

int zn_add_ref(zn_node_t *node, ldns_rdf *name, ldns_rr_type type,
               ldns_rr_list *ref_rrset, const zn_node_t *ref_node)
{
	zn_flags_t flag = 0;

	assert(ref_rrset != NULL || ref_node != NULL);
	assert(ref_node != NULL || ref_rrset != NULL);

	switch (type) {
	case LDNS_RR_TYPE_MX:
		flag = FLAGS_HAS_MX;
		break;
	case LDNS_RR_TYPE_NS:
		flag = FLAGS_HAS_NS;
		break;
	case LDNS_RR_TYPE_SRV:
		flag = FLAGS_HAS_SRV;
		break;
	default:
		log_error("zn_add_ref(): type %s not supported.\n",
		          ldns_rr_type2str(type));
		return -1;
	}

	if (node->ref.additional == NULL) {
		node->ref.additional = skip_create_list(zn_compare_ar_keys);
		if (node->ref.additional == NULL) {
			return -3;
		}
	}

	zn_ar_rrsets_t *ar;
	if (ref_rrset != NULL) {
		ar = zn_create_ar_rrsets_for_ref(ref_rrset);
	} else {
		assert(ref_node != NULL);
		ar = zn_create_ar_rrsets_for_cname(ref_node);
	}
	if (ar == NULL) {
		skip_destroy_list(&(node->ref.additional), NULL,
		                  zn_dtor_ar_rrsets);
		return -4;
	}

	int res = 0;
	res = skip_insert(node->ref.additional, name, ar, zn_merge_ar_values);
	if (res != 0) {
		debug_zn("Result other than 0, deleting ar rrset on %p\n", ar);
		zn_destroy_ar_rrsets(&ar);
	}
	zn_flags_set(&node->flags, flag);

	debug_zn("zn_add_ref(%p, %p, %s)\n", node, ref_rrset,
	         ldns_rr_type2str(type));
	debug_zn("First item in the skip list: key: %s, value: %p\n",
	         ldns_rdf2str((ldns_rdf *)skip_first(node->ref.additional)->key),
	         skip_first(node->ref.additional)->value);
	debug_zn("Inserted item: value: %p\n", ar);

	if (res < 0) {
		return -5;
	}

	return 0;
}

/*----------------------------------------------------------------------------*/

skip_list_t *zn_get_refs(const zn_node_t *node)
{
	if ((zn_flags_get(node->flags, FLAGS_HAS_MX)
	    | zn_flags_get(node->flags, FLAGS_HAS_NS)
	    | zn_flags_get(node->flags, FLAGS_HAS_SRV)) > 0) {
		return node->ref.additional;
	} else {
		return NULL;
	}
}

/*----------------------------------------------------------------------------*/

const zn_ar_rrsets_t *zn_get_ref(const zn_node_t *node, const ldns_rdf *name)
{
	if ((zn_flags_get(node->flags, FLAGS_HAS_MX)
	    | zn_flags_get(node->flags, FLAGS_HAS_NS)
	    | zn_flags_get(node->flags, FLAGS_HAS_SRV)) > 0) {
		return (zn_ar_rrsets_t *)skip_find(node->ref.additional,
		                                   (void *)name);
	} else {
		return NULL;
	}
}

/*----------------------------------------------------------------------------*/

int zn_has_mx(const zn_node_t *node)
{
	return zn_flags_get(node->flags, FLAGS_HAS_MX);
}

/*----------------------------------------------------------------------------*/

int zn_has_ns(const zn_node_t *node)
{
	return zn_flags_get(node->flags, FLAGS_HAS_NS);
}

/*----------------------------------------------------------------------------*/

int zn_has_srv(const zn_node_t *node)
{
	return zn_flags_get(node->flags, FLAGS_HAS_SRV);
}

/*----------------------------------------------------------------------------*/

int zn_add_referrer_cname(zn_node_t *node, const zn_node_t *referrer)
{
	int res = zn_add_referrer_node(node, referrer);
	if (res == 0) {
		zn_flags_set(&node->flags, FLAGS_REF_CNAME);
	}
	return res;
}

/*----------------------------------------------------------------------------*/

int zn_add_referrer_mx(zn_node_t *node, const zn_node_t *referrer)
{
	int res = zn_add_referrer_node(node, referrer);
	if (res == 0) {
		zn_flags_set(&node->flags, FLAGS_REF_MX);
	}
	return res;
}

/*----------------------------------------------------------------------------*/

int zn_add_referrer_ns(zn_node_t *node, const zn_node_t *referrer)
{
	int res = zn_add_referrer_node(node, referrer);
	if (res == 0) {
		zn_flags_set(&node->flags, FLAGS_REF_NS);
	}
	return res;
}

/*----------------------------------------------------------------------------*/

int zn_add_referrer_srv(zn_node_t *node, const zn_node_t *referrer)
{
	int res = zn_add_referrer_node(node, referrer);
	if (res == 0) {
		zn_flags_set(&node->flags, FLAGS_REF_SRV);
	}
	return res;
}

/*----------------------------------------------------------------------------*/

int zn_add_referrer(zn_node_t *node, const zn_node_t *referrer,
                    ldns_rr_type type)
{
	int res = zn_add_referrer_node(node, referrer);
	if (res == 0) {
		uint16_t flag = 0;
		switch (type) {
		case LDNS_RR_TYPE_NS:
			flag = FLAGS_REF_NS;
			break;
		case LDNS_RR_TYPE_MX:
			flag = FLAGS_REF_MX;
			break;
		case LDNS_RR_TYPE_CNAME:
			flag = FLAGS_REF_CNAME;
			break;
		case LDNS_RR_TYPE_SRV:
			flag = FLAGS_REF_SRV;
			break;
		default:
			debug_zn("zn_add_referrer(): type %s not supported.\n",
			         ldns_rr_type2str(type));
			return -2;
			break;
		}

		zn_flags_set(&node->flags, flag);
	}
	return res;
}

/*----------------------------------------------------------------------------*/

int zn_referrers_count(const zn_node_t *node)
{
	int count = RFRS_COUNT(node->referrers);
	assert(count == 0 || (zn_flags_get(node->flags, FLAGS_REF_CNAME)
	                      | zn_flags_get(node->flags, FLAGS_REF_MX)
	                      | zn_flags_get(node->flags, FLAGS_REF_NS)
	                      | zn_flags_get(node->flags, FLAGS_REF_SRV)) > 0);
	return count;
}

/*----------------------------------------------------------------------------*/

int zn_push_glue(zn_node_t *node, ldns_rr_list *glue)
{
	assert((zn_flags_get(node->flags, FLAGS_DELEG) == 1
	        && node->ref.glues != NULL));

	if (glue == NULL) {
		return 0;
	}

	int res = ldns_rr_list_push_rr_list(node->ref.glues, glue) - 1;
	if (res == 0) {
		// sort the glue RRs
		ldns_rr_list_sort(node->ref.glues);
	}
	return res;
}

/*----------------------------------------------------------------------------*/

ldns_rr_list *zn_get_glues(const zn_node_t *node)
{
	if (!zn_is_delegation_point(node)) {
		return NULL;
	}
	return node->ref.glues;
}

/*----------------------------------------------------------------------------*/

ldns_rr_list *zn_get_glue(const zn_node_t *node, ldns_rdf *owner,
                          ldns_rr_type type, ldns_rr_list *copied_rrs)
{
	assert(type == LDNS_RR_TYPE_A || type == LDNS_RR_TYPE_AAAA);

	if (!zn_is_delegation_point(node)) {
		return NULL;
	}

	assert(copied_rrs != NULL);
	ldns_rr_list *glue = ldns_rr_list_new();

	ldns_rr *rr;
	int i = -1;
	int cmp;
	do {
		++i;
		rr = ldns_rr_list_rr(node->ref.glues, i);
	} while ((cmp = ldns_dname_match_wildcard(owner, ldns_rr_owner(rr)))
	          < 0);

	// found owner
	while (cmp == 0 && ldns_rr_get_type(rr) != type) {
		++i;
		rr = ldns_rr_list_rr(node->ref.glues, i);
		cmp = ldns_dname_match_wildcard(owner, ldns_rr_owner(rr));
	}

	// found owner & type
	while (cmp == 0 && ldns_rr_get_type(rr) == type) {
		// if the RR has a wildcard owner, copy the RR and replace the
		// owner with the desired name
		if (ldns_dname_is_wildcard(ldns_rr_owner(rr))) {
			ldns_rr *rr_new = ldns_rr_clone(rr);
			ldns_rdf_deep_free(ldns_rr_owner(rr_new));
			ldns_rr_set_owner(rr_new, ldns_rdf_clone(owner));
			ldns_rr_list_push_rr(glue, rr_new);
			ldns_rr_list_push_rr(copied_rrs, rr_new);
		} else {
			ldns_rr_list_push_rr(glue, rr);
		}
		++i;
		rr = ldns_rr_list_rr(node->ref.glues, i);
		cmp = ldns_dname_compare(ldns_rr_owner(rr), owner);
	}

	return glue;
}

/*----------------------------------------------------------------------------*/

void zn_destroy(zn_node_t **node)
{
	skip_destroy_list(&(*node)->rrsets, NULL, zn_destroy_value);
	if (zn_has_additional(*node)) {
		skip_destroy_list(&(*node)->ref.additional, NULL,
		                  zn_dtor_ar_rrsets);
	}

	ldns_rdf_deep_free((*node)->owner);
	if (zn_is_delegation_point(*node)) {
		ldns_rr_list_free((*node)->ref.glues);
	}
	if ((*node)->referrers != NULL) {
		da_destroy((*node)->referrers);
		free((*node)->referrers);
	}
	free(*node);
	*node = NULL;
}

/*----------------------------------------------------------------------------*/

void zn_destructor(void *item)
{
	zn_node_t *node = (zn_node_t *)item;
	zn_destroy(&node);
}

/*----------------------------------------------------------------------------*/

void zn_print_rrset(void *key, void *value)
{
	debug_zn("Type: %d,%s, RRSet: %s\n",
	         (ldns_rr_type)key,
	         ldns_rr_type2str((ldns_rr_type)key),
	         ldns_rr_list2str((ldns_rr_list *)value));
}
