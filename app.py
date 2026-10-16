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
    "<p style='text-align: center;'>Traducción Dinámica Inteligente basada en tu"
    " Matriz Maestra</p>",
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
      "🔄 Traductor Dinámico Multi-EDR",
      "🔍 Buscador en Matriz Maestra",
      "📂 Explorador de Inventario (15,950 Campos)",
  ])

  with tab_traducir:
    st.subheader(
        "🔄 Traductor Dinámico basado en el Contenido de tu Consulta"
    )
    st.markdown(
        "Pega cualquier consulta de Threat Hunting. El motor analizará su"
        " estructura y la traducirá dinámicamente."
    )

    all_langs = {
        "kql": "Microsoft Defender XDR (KQL)",
        "xql": "Palo Alto Cortex XDR (XQL / xdr_data)",
        "cql": "CrowdStrike Falcon LogScale (CQL)",
        "trend": "Trend Vision One",
    }

    source_code = st.selectbox(
        "📥 EDR de origen de la consulta:",
        options=list(all_langs.keys()),
        format_func=lambda x: all_langs[x],
    )

    query_in = st.text_area(
        "Pega tu consulta completa aquí:",
        height=280,
        placeholder=(
            "DeviceProcessEvents\n| where Timestamp >= ago(30d)\n| where"
            " FileName == 'cmd.exe'..."
        ),
    )

    if st.button("🚀 Homologar Dinámicamente", type="primary"):
      if not query_in.strip():
        st.warning("⚠️ Ingresa una consulta válida.")
      else:
        q_clean = query_in.strip()
        q_lower = q_clean.lower()

        # Detección de contexto (Proceso vs Archivo)
        is_file_query = (
            "file" in q_lower
            or "folderpath" in q_lower
            or "filename" in q_lower
            and "process" not in q_lower
        )

        # --- 1. TRADUCCIÓN DINÁMICA A XQL (Palo Alto) ---
        with st.expander(
            "🎯 Palo Alto Cortex XDR (XQL / xdr_data)", expanded=True
        ):
          xql = "config case_sensitive = false\n| dataset = xdr_data"
          if is_file_query:
            xql += "\n| filter event_type = ENUM.FILE"
          else:
            xql += "\n| filter event_type = ENUM.PROCESS"

          for line in q_clean.split("\n"):
            l_strip = line.strip()
            l_l = l_strip.lower()

            if (
                not l_strip
                or "deviceprocessevents" in l_l
                or "devicefileevents" in l_l
            ):
              continue
            if "timestamp" in l_l and "ago" in l_l:
              xql += "\n// [Ventana temporal gestionada por el selector de consola]"
              continue

            # Reemplazos sintácticos y de campos
            l_tr = (
                l_strip.replace("| where", "| filter")
                .replace("| project", "| fields")
                .replace("| extend", "| alter")
                .replace("| order by", "| sort")
                .replace("Timestamp", "_time")
                .replace("DeviceName", "agent_hostname")
                .replace("AccountName", "actor_primary_username")
                .replace("FileName", "action_file_name")
                .replace("FolderPath", "action_file_path")
                .replace("ProcessCommandLine", "action_process_command_line")
                .replace(
                    "InitiatingProcessFileName", "actor_process_image_name"
                )
                .replace(
                    "InitiatingProcessFolderPath", "actor_process_image_path"
                )
                .replace(
                    "InitiatingProcessCommandLine",
                    "actor_process_command_line",
                )
                .replace("SHA1", "action_file_sha1")
            )
            xql += "\n" + l_tr
          st.code(xql, language="sql")

        # --- 2. TRADUCCIÓN DINÁMICA A KQL (Defender) ---
        with st.expander("🎯 Microsoft Defender XDR (KQL)"):
          if source_code == "kql":
            kql = q_clean
          else:
            kql = q_clean  # Si viene de otro origen, se muestra o adapta
          st.code(kql, language="kusto")

        # --- 3. TRADUCCIÓN DINÁMICA A CROWDSTRIKE (CQL) ---
        with st.expander("🎯 CrowdStrike Falcon LogScale (CQL)"):
          cql = (
              "#event_simpleName=ProcessRollup2\nevent_platform=Win"
              if not is_file_query
              else "#event_simpleName=FileCreateInfo"
          )
          for line in q_clean.split("\n"):
            l_strip = line.strip()
            l_l = l_strip.lower()
            if (
                not l_strip
                or "deviceprocessevents" in l_l
                or "devicefileevents" in l_l
                or "timestamp" in l_l
            ):
              continue
            l_tr = (
                l_strip.replace("| where", "|")
                .replace("| project", "| table(")
                .replace("DeviceName", "ComputerName")
                .replace("AccountName", "UserName")
                .replace("FileName", "FileName")
                .replace("FolderPath", "TargetFileName")
                .replace("ProcessCommandLine", "CommandLine")
            )
            if "| table(" in l_tr and not l_tr.endswith(")"):
              l_tr += ")"
            cql += "\n" + l_tr
          st.code(cql, language="text")

        # --- 4. TRADUCCIÓN DINÁMICA A TREND VISION ONE ---
        with st.expander("🎯 Trend Vision One"):
          trend = "#trendVisionOneQuery"
          for line in q_clean.split("\n"):
            l_strip = line.strip()
            l_l = l_strip.lower()
            if (
                not l_strip
                or "deviceprocessevents" in l_l
                or "devicefileevents" in l_l
                or "timestamp" in l_l
            ):
              continue
            l_tr = (
                l_strip.replace("| where", "| filter")
                .replace("| project", "| select")
                .replace("DeviceName", "endpointHostName")
                .replace("FileName", "objectFileName")
                .replace("FolderPath", "objectFilePath")
                .replace("ProcessCommandLine", "objectCmd")
            )
            trend += "\n" + l_tr
          st.code(trend, language="text")

        # --- 5. FUENTES Y REFERENCIAS ---
        with st.expander("📚 Fuentes y Referencias Oficiales de Esquemas"):
          st.markdown("""
          - **Microsoft Defender XDR (KQL):** [Advanced Hunting Schema Tables](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables)
          - **Palo Alto Cortex XDR (XQL):** Documentación oficial de datasets y campos en el diccionario adjunto.
          - **CrowdStrike Falcon LogScale (CQL):** Guía de eventos y sintaxis LogScale / FDR.
          - **Trend Vision One:** [Search Syntax & General Search Documentation](https://docs.trendmicro.com/fr-fr/documentation/article/trend-vision-one-search-syntax)
          - **Cytomic Orion:** [Management & Investigation Guide](https://info.cytomicmodel.com/resources/help/EDR/v17/en/Content/09_manage_computer_devices/investigation_section.htm)
          """)

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
