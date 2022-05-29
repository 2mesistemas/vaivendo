connect pje2_homologacao_1g;

SELECT
  ti.id_ as id,
  ti.name_ as tarefa,
  ti.create_ as inicio_tarefa,
  ti.end_ as fim_tarefa,
  (
    EXTRACT (EPOCH
    FROM ti.end_) - EXTRACT(EPOCH
    FROM ti.create_)
  ) / 3600 as tempo_execucao,
  usu.ds_nome as finalizada_por,
  ti.isopen_ as aberta,
  pd.name_ as fluxo,
  proc.nr_processo as processo
FROM jbpm_taskinstance ti
INNER JOIN core.tb_processo_instance tpi ON tpi.id_proc_inst = ti.procinst_
LEFT JOIN core.tb_processo proc on proc.id_processo = tpi.id_proc_inst
INNER JOIN jbpm_processinstance pi ON ti.procinst_ = pi.id_
INNER JOIN jbpm_processdefinition pd on pi.processdefinition_ = pd.id_
LEFT JOIN acl.tb_usuario_login usu ON usu.ds_login = ti.actorid_
ORDER BY
  create_;

select
  *
from acl.tb_usuario_login;

select
  *
from core.tb_usuario_localizacao
where
  id_usuario = 57359;

select
  *
from client.tb_usu_local_mgtdo_servdor
where
  id_usu_local_mgstrado_servidor = 57359;

/**
  Creating the schema ANALYTICS
*/
create schema analytics;

create materialized view analytics.historico_tarefas_processo as
SELECT
  ti.id_ as id,
  ti.name_ as tarefa,
  ti.create_ as inicio_tarefa,
  ti.end_ as fim_tarefa,
  (
    EXTRACT (EPOCH FROM ti.end_) - EXTRACT(EPOCH FROM ti.create_)
  ) / 3600 as tempo_execucao,
  usu.ds_nome as finalizada_por,
  ti.isopen_ as aberta,
  pd.name_ as fluxo,
  proc.nr_processo as processo
FROM jbpm_taskinstance ti
INNER JOIN core.tb_processo_instance tpi ON tpi.id_proc_inst = ti.procinst_
LEFT JOIN core.tb_processo proc on proc.id_processo = tpi.id_proc_inst
INNER JOIN jbpm_processinstance pi ON ti.procinst_ = pi.id_
INNER JOIN jbpm_processdefinition pd on pi.processdefinition_ = pd.id_
LEFT JOIN acl.tb_usuario_login usu ON usu.ds_login = ti.actorid_
order by ti.create_ with data;


select * from analytics.historico_tarefas_processo;

drop materialized view analytics.historico_tarefas_processo;

select count(*) from analytics.historico_tarefas_processo;


create materialized view analytics.processo_documento as
SELECT proc_doc.id_processo_documento,
  proc_doc.ds_processo_documento,
  proc_doc.nr_documento,
  date_trunc('day', proc_doc.dt_inclusao) as dt_inclusao,
  to_char(proc_doc.dt_inclusao, 'dd/MM/yyyy') as dt_inclusao_formatada,
  proc_doc.ds_nome_usuario_inclusao,
  proc_doc.id_localizacao,
  proc_doc.ds_nome_localizacao,
  proc.*,
  'DECISÃO' as tipo_documento
FROM core.tb_processo_documento proc_doc
  LEFT JOIN core.tb_processo proc on proc.id_processo = proc_doc.id_processo
WHERE id_tipo_processo_documento = (
    SELECT vl_variavel::integer
    FROM core.tb_parametro
    WHERE nm_variavel = 'idTipoProcessoDocumentoDecisao'
  )
union all
SELECT proc_doc.id_processo_documento,
  proc_doc.ds_processo_documento,
  proc_doc.nr_documento,
  date_trunc('day', proc_doc.dt_inclusao) as dt_inclusao,
  to_char(proc_doc.dt_inclusao, 'dd/MM/yyyy') as dt_inclusao_formatada,
  proc_doc.ds_nome_usuario_inclusao,
  proc_doc.id_localizacao,
  proc_doc.ds_nome_localizacao,
  proc.*,
  'SENTENÇA' as tipo_documento
FROM core.tb_processo_documento proc_doc
  LEFT JOIN core.tb_processo proc on proc.id_processo = proc_doc.id_processo
WHERE id_tipo_processo_documento = (
    SELECT vl_variavel::integer
    FROM core.tb_parametro
    WHERE nm_variavel = 'idTipoProcessoDocumentoSentenca'
  )
union all
SELECT proc_doc.id_processo_documento,
  proc_doc.ds_processo_documento,
  proc_doc.nr_documento,
  date_trunc('day', proc_doc.dt_inclusao) as dt_inclusao,
  to_char(proc_doc.dt_inclusao, 'dd/MM/yyyy') as dt_inclusao_formatada,
  proc_doc.ds_nome_usuario_inclusao,
  proc_doc.id_localizacao,
  proc_doc.ds_nome_localizacao,
  proc.*,
  'DESPACHO' as tipo_documento
FROM core.tb_processo_documento proc_doc
  LEFT JOIN core.tb_processo proc on proc.id_processo = proc_doc.id_processo
WHERE id_tipo_processo_documento = (
    SELECT vl_variavel::integer
    FROM core.tb_parametro
    WHERE nm_variavel = 'idTipoProcessoDocumentoDespacho'
  );

--postgresql://usuariohoml:hml12#TT@zincod03.cnj.jus.br:6432/pje_cnj_prod


----
-- Configuração da role com suas permissões superset no banco de dados
----

select
  role.id as role_id,
  role.name as role_name,
  permission_role.id as "permrole-id",
  permission_role.permission_view_id as "permrole-permission_view_id",
  permission_role.role_id as "permrole-role_id",
  permv.id as permv_id,
  permv.permission_id as "permv-permission_id",
  permv.view_menu_id as "permv-view_menu_id",
  perm.id as "perm-id",
  perm.name as "perm-name"
from ab_role role
inner join ab_permission_view_role permission_role on role.id = permission_role.role_id
inner join ab_permission_view permv on permv.id = permission_role.permission_view_id
inner join ab_permission perm on perm.id = permv.permission_id
where
  role.id = 2;

/**
role_id | role_name | permrole-id | permrole-permission_view_id | permrole-role_id | permv_id | permv-permission_id | permv-view_menu_id | perm-id | perm-name
2	Public	589	129	2	129	44	46	44	can_dashboard
2	Public	611	153	2	153	68	46	68	can_explore_json
2	Public	1333	207	2	207	84	72	84	all_datasource_access
2	Public	1334	208	2	208	85	73	85	all_database_access
**/


/**
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 16, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 17, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 18, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 19, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 21, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 43, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 44, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 45, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 46, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 47, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 48, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 57, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 58, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 59, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 60, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 65, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 68, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 70, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 72, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 73, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 74, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 75, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 76, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 77, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 79, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 80, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 81, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 82, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 83, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 85, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 86, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 87, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 88, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 90, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 106, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 114, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 119, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 121, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 122, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 124, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 125, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 126, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 129, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 130, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 133, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 134, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 135, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 137, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 139, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 140, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 141, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 142, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 143, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 145, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 146, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 147, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 148, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 149, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 150, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 151, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 152, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 153, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 154, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 157, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 164, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 165, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 176, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 177, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 178, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 179, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 180, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 181, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 182, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 207, 2);
insert into ab_permission_view_role (id, permission_view_id, role_id) values ((select max(id) + 1 from ab_permission_view_role), 208, 2);



2;"Public";1806;16;2;16;3;19;3;"can_this_form_post"
2;"Public";1807;17;2;17;4;19;4;"can_this_form_get"
2;"Public";1808;18;2;18;3;20;3;"can_this_form_post"
2;"Public";1809;19;2;19;4;20;4;"can_this_form_get"
2;"Public";1810;21;2;21;6;22;6;"can_userinfo"
2;"Public";1819;43;2;43;5;28;5;"can_edit"
2;"Public";1820;44;2;44;16;28;16;"can_mulexport"
2;"Public";1821;45;2;45;7;28;7;"can_delete"
2;"Public";1822;46;2;46;9;28;9;"can_list"
2;"Public";1823;47;2;47;8;28;8;"can_add"
2;"Public";1824;48;2;48;10;28;10;"can_show"
2;"Public";1832;57;2;57;7;31;7;"can_delete"
2;"Public";1833;58;2;58;8;31;8;"can_add"
2;"Public";1834;59;2;59;9;31;9;"can_list"
2;"Public";1835;60;2;60;10;31;10;"can_show"
2;"Public";1836;65;2;65;10;29;10;"can_show"
2;"Public";1837;68;2;68;19;27;19;"can_download"
2;"Public";1838;70;2;70;20;28;20;"can_download_dashboards"
2;"Public";1839;72;2;72;21;28;21;"mulexport"
2;"Public";1840;73;2;73;5;32;5;"can_edit"
2;"Public";1841;74;2;74;7;32;7;"can_delete"
2;"Public";1842;75;2;75;8;32;8;"can_add"
2;"Public";1843;76;2;76;9;32;9;"can_list"
2;"Public";1844;77;2;77;10;32;10;"can_show"
2;"Public";1845;79;2;79;9;33;9;"can_list"
2;"Public";1846;80;2;80;10;33;10;"can_show"
2;"Public";1847;81;2;81;22;34;22;"can_query"
2;"Public";1848;82;2;82;23;34;23;"can_query_form_data"
2;"Public";1849;83;2;83;9;35;9;"can_list"
2;"Public";1850;85;2;85;3;36;3;"can_this_form_post"
2;"Public";1851;86;2;86;4;36;4;"can_this_form_get"
2;"Public";1852;87;2;87;24;37;24;"can_new"
2;"Public";1853;88;2;88;9;38;9;"can_list"
2;"Public";1854;90;2;90;21;38;21;"mulexport"
2;"Public";1867;106;2;106;9;43;9;"can_list"
2;"Public";1871;114;2;114;29;46;29;"can_annotation_json"
2;"Public";1876;119;2;119;34;46;34;"can_slice_query"
2;"Public";1878;121;2;121;36;46;36;"can_stop_query"
2;"Public";1879;122;2;122;37;46;37;"can_user_slices"
2;"Public";1881;124;2;124;39;46;39;"can_csv"
2;"Public";1882;125;2;125;40;46;40;"can_results"
2;"Public";1883;126;2;126;41;46;41;"can_schemas_access_for_csv_upload"
2;"Public";589; 129;2;129;44;46;44;"can_dashboard"
2;"Public";1885;130;2;130;45;46;45;"can_queries"
2;"Public";1887;133;2;133;48;46;48;"can_datasources"
2;"Public";1888;134;2;134;49;46;49;"can_fave_dashboards"
2;"Public";1889;135;2;135;50;46;50;"can_slice_json"
2;"Public";1891;137;2;137;52;46;52;"can_validate_sql_json"
2;"Public";1892;139;2;139;54;46;54;"can_extra_table_metadata"
2;"Public";1893;140;2;140;55;46;55;"can_explore"
2;"Public";1894;141;2;141;56;46;56;"can_sqllab_viz"
2;"Public";1895;142;2;142;57;46;57;"can_tables"
2;"Public";1896;143;2;143;58;46;58;"can_copy_dash"
2;"Public";1898;145;2;145;60;46;60;"can_filter"
2;"Public";1899;146;2;146;61;46;61;"can_fetch_datasource_metadata"
2;"Public";1900;147;2;147;62;46;62;"can_favstar"
2;"Public";1901;148;2;148;63;46;63;"can_warm_up_cache"
2;"Public";1902;149;2;149;64;46;64;"can_request_access"
2;"Public";1903;150;2;150;65;46;65;"can_estimate_query_cost"
2;"Public";1904;151;2;151;66;46;66;"can_recent_activity"
2;"Public";1905;152;2;152;67;46;67;"can_search_queries"
2;"Public";611; 153;2;153;68;46;68;"can_explore_json"
2;"Public";1906;154;2;154;69;46;69;"can_slice"
2;"Public";1909;157;2;157;72;46;72;"can_select_star"
2;"Public";1912;164;2;164;9;47;9;"can_list"
2;"Public";1913;165;2;165;10;47;10;"can_show"
2;"Public";1918;176;2;176;78;49;78;"can_expanded"
2;"Public";1919;177;2;177;15;50;15;"can_get"
2;"Public";1920;178;2;178;79;50;79;"can_activate"
2;"Public";1921;179;2;179;80;50;80;"can_delete_query"
2;"Public";1922;180;2;180;77;50;77;"can_post"
2;"Public";1923;181;2;181;7;50;7;"can_delete"
2;"Public";1924;182;2;182;81;50;81;"can_put"
2;"Public";1941;207;2;207;84;72;84;"all_datasource_access"
2;"Public";1942;208;2;208;85;73;85;"all_database_access"



**/
