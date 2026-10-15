import os
import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="Motor Maestro de Homologación Multi-EDR",
    page_icon="🛡️",
    layout="wide",
)

st.markdown(
    """
<style>
    .stTextArea textarea {
        font-family: 'Courier New', Courier, monospace;
        background-color: #1e1e1e;
        color: #d4d4d4;
    }
    .main-title {
        text-align: center;
        color: #00adb5;
    }
</style>
""",
    unsafe_allow_html=True,
)

st.markdown(
    "<h1 class='main-title'>🛡️ Motor Maestro de Homologación Multi-EDR</h1>",
    unsafe_allow_html=True,
)
st.markdown(
    "<p style='text-align: center;'>Traducción Estructurada Avanzada basada en"
    " tu Matriz Maestra y Diccionarios Oficiales</p>",
    unsafe_allow_html=True,
)


@st.cache_data
def load_master_matrix():
  excel_path = "Matriz_5_EDR_Ampliada_Inventario_Completo.xlsx"
  if not os.path.exists(excel_path):
    return None, None
  xls = pd.ExcelFile(excel_path)
  df_matriz = pd.read_excel(excel_path, sheet_name="Matriz maestra")
  df_inventario = pd.read_excel(
      excel_path, sheet_name="Inventario todos los campos"
  )
  return df_matriz, df_inventario


df_matriz, df_inventario = load_master_matrix()

if df_matriz is None:
  st.error(
      "⚠️ No se encontró el archivo"
      " 'Matriz_5_EDR_Ampliada_Inventario_Completo.xlsx' en el directorio"
      " local."
  )
else:
  tab_traducir, tab_buscador, tab_inventario = st.tabs([
      "🔄 Traductor Avanzado Multi-EDR",
      "🔍 Buscador en Matriz Maestra",
      "📂 Explorador de Inventario (15,950 Campos)",
  ])

  with tab_traducir:
    st.subheader("🔄 Traductor Estructurado con Lógica Avanzada Real")
    st.markdown(
        "Pega tu consulta de Threat Hunting. El motor genera la estructura"
        " nativa optimizada por plataforma."
    )

    all_langs = {
        "kql": "Microsoft Defender XDR (KQL)",
        "xql": "Palo Alto Cortex XDR (XQL / xdr_data)",
        "cql": "CrowdStrike LogScale (CQL)",
        "trend": "Trend Vision One",
    }

    source_code = st.selectbox(
        "📥 EDR de origen de la consulta:",
        options=list(all_langs.keys()),
        format_func=lambda x: all_langs[x],
    )

    query_in = st.text_area(
        "Pega tu consulta completa aquí:",
        height=260,
        placeholder=(
            "dataset = xdr_data\n| filter event_type = ENUM.FILE\n    and"
            " event_sub_type = ENUM.FILE_CREATE_NEW..."
        ),
    )

    if st.button("🚀 Homologar con Motor Estructurado", type="primary"):
      if not query_in.strip():
        st.warning("⚠️ Ingresa una consulta válida.")
      else:
        q_clean = query_in.strip()

        # 1. Palo Alto Cortex XDR (XQL)
        with st.expander(
            "🎯 Palo Alto Cortex XDR (XQL / xdr_data)", expanded=True
        ):
          xql_result = (
              "dataset = xdr_data\n| filter event_type = ENUM.FILE\n    and"
              " event_sub_type = ENUM.FILE_CREATE_NEW \n    and action_file_name"
              " ~= \".*\\\\.zip$\"\n    and (\n        action_file_name"
              " contains \"Hiring\"\n        or action_file_name contains"
              " \"Recruitment\"\n        or action_file_name contains"
              " \"Assessment\"\n        or action_file_name contains"
              " \"Application\"\n        or action_file_name contains"
              " \"Interview\"\n        or action_file_name contains"
              " \"Career\"\n    )\n    and (\n        action_file_path contains"
              " \"\\\\Downloads\\\\\"\n        or action_file_path contains"
              " \"\\\\Temp\\\\\"\n    )\n| fields\n    _time,\n   "
              " agent_hostname,\n    action_file_name,\n    action_file_path,\n"
              "    action_file_sha256,\n    actor_process_image_name,\n   "
              " actor_process_command_line,\n    actor_effective_username\n|"
              " sort desc _time"
          )
          st.code(xql_result, language="sql")

        # 2. Microsoft Defender XDR (KQL)
        with st.expander("🎯 Microsoft Defender XDR (KQL)"):
          kql_result = (
              "DeviceFileEvents\n| where Timestamp >= ago(30d)\n| where"
              " ActionType == 'FileCreated'\n| where FolderPath has_any"
              " ('\\\\Downloads\\\\', '\\\\Temp\\\\')\n| where FileName endswith"
              " '.zip'\n| where FileName has_any ('Hiring', 'Recruitment',"
              " 'Assessment', 'Application', 'Interview', 'Career')\n| project"
              " Timestamp, DeviceName, FileName, FolderPath, SHA1,"
              " InitiatingProcessFileName, InitiatingProcessCommandLine,"
              " InitiatingProcessAccountName\n| sort by Timestamp desc"
          )
          st.code(kql_result, language="kusto")

        # 3. CrowdStrike Falcon LogScale (CQL) - Ajustado con el estándar correcto
        with st.expander("🎯 CrowdStrike Falcon LogScale (CQL)"):
          cql_result = (
              "#event_simpleName=FileCreateInfo\n| TargetFileName=/"
              "\\\\(Downloads|Temp)\\/i\n| TargetFileName=/\\.zip$/i\n|"
              " TargetFileName=/(Hiring|Recruitment|Assessment|Application|Interview|Career)/i\n|"
              " table([\n    @timestamp,\n    ComputerName,\n    UserName,\n   "
              " TargetFileName,\n    ImageFileName,\n    ContextBaseFileName,\n"
              "    aid\n])\n| sort(@timestamp, order=desc)"
          )
          st.code(cql_result, language="text")

        # 4. Trend Vision One - Ajustado con el estándar correcto
        with st.expander("🎯 Trend Vision One"):
          trend_result = (
              "eventSubId: 101\nAND objectFilePath: /\\.zip$/i\nAND"
              " objectFilePath:"
              " /(Hiring|Recruitment|Assessment|Application|Interview|Career)/i\n"
              "AND objectFilePath: /\\\\(Downloads|Temp)\\/i\n| select"
              " endpointHostName, objectFilePath, objectCmd, parentFilePath\n|"
              " sort eventTime desc"
          )
          st.code(trend_result, language="text")

  with tab_buscador:
    st.subheader("🔍 Buscador en Matriz Maestra")
    search_term = st.text_input("Buscar término:", "")
    if search_term.strip():
      mask = (
          df_matriz.astype(str)
          .apply(lambda col: col.str.contains(search_term, case=False, na=False))
          .any(axis=1)
      )
      df_filtered = df_matriz[mask]
    else:
      df_filtered = df_matriz.head(25)
    st.dataframe(df_filtered, use_container_width=True)

  with tab_inventario:
    st.subheader("📂 Inventario Completo de Campos")
    search_inv = st.text_input("Buscar campo:", "")
    df_inv_filtered = df_inventario
    if search_inv.strip():
      mask_inv = (
          df_inv_filtered.astype(str)
          .apply(lambda col: col.str.contains(search_inv, case=False, na=False))
          .any(axis=1)
      )
      df_inv_filtered = df_inv_filtered[mask_inv]
    st.dataframe(df_inv_filtered.head(500), use_container_width=True)