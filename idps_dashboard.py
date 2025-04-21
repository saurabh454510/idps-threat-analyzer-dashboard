#!/usr/bin/env python3
"""
Professional IDPS Dashboard with CSV Upload
Enhanced with advanced attack classification
"""

import os
import base64
import io
import logging
import pandas as pd
import numpy as np
import dash
from dash import dcc, html, Input, Output, State, dash_table, callback
import dash_bootstrap_components as dbc
from dash.exceptions import PreventUpdate
import plotly.express as px
import plotly.graph_objects as go
from tensorflow.keras.models import load_model

# ======================
# CONFIGURATION
# ======================
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'  # Suppress TensorFlow messages

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ======================
# MODEL LOADING
# ======================
try:
    logger.info("Loading IDPS model...")
    model = load_model('idps_full_model.h5')
    logger.info("Model loaded successfully")
except Exception as e:
    logger.error(f"Model loading failed: {str(e)}")
    raise

# ======================
# FEATURE DEFINITIONS
# ======================
FEATURES = [
    'destination_port', 'flow_duration', 'total_fwd_packets', 'total_backward_packets',
    'total_length_fwd_packets', 'total_length_bwd_packets', 'fwd_packet_length_max',
    'fwd_packet_length_min', 'fwd_packet_length_mean', 'fwd_packet_length_std',
    'bwd_packet_length_max', 'bwd_packet_length_min', 'bwd_packet_length_mean',
    'bwd_packet_length_std', 'flow_bytes_per_sec', 'flow_packets_per_sec',
    'flow_iat_mean', 'flow_iat_std', 'flow_iat_max', 'flow_iat_min',
    'fwd_iat_total', 'fwd_iat_mean', 'fwd_iat_std', 'fwd_iat_max', 'fwd_iat_min',
    'bwd_iat_total', 'bwd_iat_mean', 'bwd_iat_std', 'bwd_iat_max', 'bwd_iat_min',
    'fwd_psh_flags', 'bwd_psh_flags', 'fwd_urg_flags', 'bwd_urg_flags',
    'fwd_header_length', 'bwd_header_length', 'fwd_packets_per_sec',
    'bwd_packets_per_sec', 'min_packet_length', 'max_packet_length',
    'packet_length_mean', 'packet_length_std', 'packet_length_variance',
    'fin_flag_count', 'syn_flag_count', 'rst_flag_count', 'psh_flag_count',
    'ack_flag_count', 'urg_flag_count', 'cwe_flag_count', 'ece_flag_count',
    'down_up_ratio', 'average_packet_size', 'avg_fwd_segment_size',
    'avg_bwd_segment_size', 'fwd_header_length_1', 'fwd_avg_bytes_per_bulk',
    'fwd_avg_packets_per_bulk', 'fwd_avg_bulk_rate', 'bwd_avg_bytes_per_bulk',
    'bwd_avg_packets_per_bulk', 'bwd_avg_bulk_rate', 'subflow_fwd_packets',
    'subflow_fwd_bytes', 'subflow_bwd_packets', 'subflow_bwd_bytes',
    'init_win_bytes_forward', 'init_win_bytes_backward', 'act_data_pkt_fwd',
    'min_seg_size_forward', 'active_mean', 'active_std', 'active_max',
    'active_min', 'idle_mean', 'idle_std', 'idle_max', 'idle_min'
]

# ======================
# ATTACK CLASSIFICATION
# ======================
def classify_attack(row):
    """Advanced attack classification using dashboard features"""
    
    # Convert row to dict if it's a pandas Series
    if hasattr(row, 'to_dict'):
        row = row.to_dict()
    
    # Helper function with safe value access
    def get(feature, default=0):
        return row.get(feature, default)

    # 1. SYN Flood Detection
    if (get('syn_flag_count') > 0.8 and 
        get('ack_flag_count') < 0.2 and 
        get('flow_duration') < 1000 and 
        get('total_fwd_packets') > 500):
        return "SYN Flood"

    # 2. DDoS Detection
    if (get('total_fwd_packets') > 1000 and 
        get('flow_duration') < 100 and 
        get('flow_packets_per_sec') > 500):
        return "DDoS Attack"

    # 3. Port Scanning
    if (get('fwd_packet_length_mean') < 50 and 
        get('flow_packets_per_sec') > 500 and 
        get('destination_port') < 1024):
        return "Port Scanning"

    # 4. Brute Force (SSH/Telnet)
    if get('destination_port') in [22, 23] and get('total_fwd_packets') > 50:
        if (get('packet_length_mean') < 100 and 
            get('flow_iat_mean') < 1000):
            return "Brute Force Attempt"

    # 5. Web Attacks
    if get('destination_port') in [80, 443, 8080]:
        if (get('bwd_packet_length_mean') > 1500 and 
            get('flow_bytes_per_sec') > 1000000):
            return "HTTP Flood"
        
        if (get('fwd_header_length') > 800 and 
            get('fwd_packets_per_sec') < 10):
            return "Slowloris Attack"

    # 6. Suspicious Activity
    if (get('urg_flag_count') > 0.5 or 
        get('fwd_psh_flags') > 0.7 or 
        get('packet_length_variance') > 500):
        return "Suspicious Activity"

    # 7. Data Exfiltration
    if (get('bwd_packets_per_sec') > 100 and 
        get('bwd_packet_length_mean') > 1000 and 
        get('flow_duration') > 3600):
        return "Possible Data Exfiltration"

    # 8. Network Probe
    if (get('total_fwd_packets') < 100 and 
        get('active_mean') < 50 and 
        get('fwd_packet_length_min') < 40):
        return "Network Probing"

    return "Normal Traffic"

# ======================
# DASH APPLICATION
# ======================
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.BOOTSTRAP])
app.title = "IDPS Threat Analyzer"
server = app.server

# ======================
# HELPER FUNCTIONS
# ======================
def create_gauge(value=0):
    """Create a threat probability gauge chart"""
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=value,
        domain={'x': [0, 1], 'y': [0, 1]},
        gauge={
            'axis': {'range': [0, 1]},
            'steps': [
                {'range': [0, 0.4], 'color': "green"},
                {'range': [0.4, 0.6], 'color': "yellow"},
                {'range': [0.6, 1], 'color': "red"}
            ],
            'threshold': {
                'line': {'color': "black", 'width': 4},
                'thickness': 0.75,
                'value': 0.5
            }
        }
    ))
    fig.update_layout(title_text="Threat Probability")
    return fig

# ======================
# LAYOUT COMPONENTS
# ======================
upload_card = dbc.Card([
    dbc.CardHeader("Upload Network Traffic Data", className="bg-primary text-white"),
    dbc.CardBody([
        dcc.Upload(
            id='upload-data',
            children=html.Div(['Drag and Drop or ', html.A('Select CSV File')]),
            style={
                'width': '100%',
                'height': '60px',
                'lineHeight': '60px',
                'borderWidth': '1px',
                'borderStyle': 'dashed',
                'borderRadius': '5px',
                'textAlign': 'center',
                'margin': '10px 0'
            },
            multiple=False
        ),
        dbc.Alert(
            "File must contain all 78 features with correct column names",
            color="info",
            className="mt-2"
        )
    ])
])

results_card = dbc.Card([
    dbc.CardHeader("Analysis Results", className="bg-primary text-white"),
    dbc.CardBody([
        dbc.Tabs([
            dbc.Tab(label="Summary", tab_id="summary"),
            dbc.Tab(label="Detailed Results", tab_id="detailed"),
        ], id="results-tabs", active_tab="summary"),
        html.Div(id="results-tab-content", className="mt-3")
    ])
])

threat_card = dbc.Card([
    dbc.CardHeader("Threat Analysis", className="bg-danger text-white"),
    dbc.CardBody([
        dcc.Graph(id="threat-gauge", figure=create_gauge()),
        html.Div(id="threat-description", className="mt-3")
    ])
])

app.layout = dbc.Container([
    dbc.Navbar(
        dbc.Container([
            dbc.NavbarBrand("IDPS Threat Analyzer", className="ms-2"),
            dbc.Nav([
                dbc.NavItem(dbc.NavLink("Documentation", href="#")),
                dbc.NavItem(dbc.NavLink("About", href="#")),
            ], className="ms-auto")
        ]),
        color="primary",
        dark=True
    ),
    
    dbc.Row([
        dbc.Col(upload_card, width=12, className="my-4")
    ]),
    
    dbc.Row([
        dbc.Col(results_card, width=8),
        dbc.Col(threat_card, width=4)
    ], className="mb-4"),
    
    dcc.Store(id='uploaded-data-store'),
    dcc.Store(id='predictions-store')
], fluid=True)

# ======================
# CALLBACKS
# ======================
@callback(
    Output('uploaded-data-store', 'data'),
    Input('upload-data', 'contents'),
    State('upload-data', 'filename')
)
def parse_upload(contents, filename):
    if contents is None:
        raise PreventUpdate
    
    content_type, content_string = contents.split(',')
    decoded = base64.b64decode(content_string)
    
    try:
        if 'csv' in filename:
            df = pd.read_csv(io.StringIO(decoded.decode('utf-8')))
        else:
            return None
        
        # Validate columns
        missing = [f for f in FEATURES if f not in df.columns]
        if missing:
            raise ValueError(f"Missing features: {', '.join(missing[:3])}...")
            
        return df.to_dict('records')
    
    except Exception as e:
        logger.error(f"Upload error: {str(e)}")
        return None

@callback(
    Output('predictions-store', 'data'),
    Input('uploaded-data-store', 'data')
)
def make_predictions(data):
    if data is None:
        raise PreventUpdate
    
    try:
        df = pd.DataFrame(data)
        X = df[FEATURES].values
        preds = model.predict(X)
        
        results = []
        for i, pred in enumerate(preds):
            results.append({
                'id': i+1,
                'probability': float(pred[0]),
                'classification': 'Attack' if pred[0] > 0.5 else 'Normal',
                'attack_type': classify_attack(df.iloc[i]) if pred[0] > 0.5 else None
            })
        
        return results
    
    except Exception as e:
        logger.error(f"Prediction error: {str(e)}")
        return None

@callback(
    Output('results-tab-content', 'children'),
    Input('results-tabs', 'active_tab'),
    Input('predictions-store', 'data'),
    Input('uploaded-data-store', 'data')
)
def render_tab_content(tab, predictions, data):
    if not predictions or not data:
        return dbc.Alert("Upload data to see results", color="secondary")
    
    df = pd.DataFrame(data)
    pred_df = pd.DataFrame(predictions)
    
    if tab == "summary":
        attack_count = pred_df[pred_df['classification'] == 'Attack'].shape[0]
        attack_types = pred_df['attack_type'].value_counts()
        
        return html.Div([
            dbc.Row([
                dbc.Col(dbc.Card([
                    dbc.CardHeader("Total Records"),
                    dbc.CardBody(html.H3(len(df), className="text-center"))
                ]), width=3),
                
                dbc.Col(dbc.Card([
                    dbc.CardHeader("Attacks Detected"),
                    dbc.CardBody(html.H3(attack_count, className="text-center text-danger"))
                ]), width=3),
                
                dbc.Col(dbc.Card([
                    dbc.CardHeader("Attack Rate"),
                    dbc.CardBody(html.H3(f"{attack_count/len(df):.1%}", className="text-center"))
                ]), width=3),
                
                dbc.Col(dbc.Card([
                    dbc.CardHeader("Avg Probability"),
                    dbc.CardBody(html.H3(f"{pred_df['probability'].mean():.2f}", className="text-center"))
                ]), width=3),
            ], className="mb-4"),
            
            dbc.Row([
                dbc.Col(dcc.Graph(
                    figure=px.histogram(
                        pred_df,
                        x='probability',
                        nbins=20,
                        title='Threat Probability Distribution',
                        color='classification',
                        color_discrete_map={'Attack': 'red', 'Normal': 'green'}
                    )
                ), width=6),
                
                dbc.Col(dcc.Graph(
                    figure=px.pie(
                        names=attack_types.index,
                        values=attack_types.values,
                        title='Attack Type Distribution',
                        hole=0.3
                    )
                ), width=6)
            ])
        ])
    
    elif tab == "detailed":
        return dash_table.DataTable(
            data=pred_df.to_dict('records'),
            columns=[
                {'name': 'ID', 'id': 'id'},
                {'name': 'Probability', 'id': 'probability', 'format': {'specifier': '.3f'}},
                {'name': 'Classification', 'id': 'classification'},
                {'name': 'Attack Type', 'id': 'attack_type'}
            ],
            page_size=10,
            style_table={'overflowX': 'auto'},
            style_data_conditional=[
                {
                    'if': {'filter_query': '{classification} = "Attack"'},
                    'backgroundColor': 'rgba(255, 0, 0, 0.1)'
                },
                {
                    'if': {'filter_query': '{attack_type} = "SYN Flood"'},
                    'backgroundColor': 'rgba(255, 100, 100, 0.3)'
                }
            ]
        )

@callback(
    [Output('threat-gauge', 'figure'),
     Output('threat-description', 'children')],
    Input('predictions-store', 'data')
)
def update_threat_display(predictions):
    if not predictions:
        return create_gauge(0), html.P("No data available")
    
    pred_df = pd.DataFrame(predictions)
    avg_prob = pred_df['probability'].mean()
    
    threat_desc = []
    if avg_prob > 0.5:
        attack_types = pred_df[pred_df['classification'] == 'Attack']['attack_type'].value_counts()
        threat_desc.append(html.H5("Detected Attack Patterns:", className="text-danger"))
        threat_desc.append(html.Ul([
            html.Li(f"{k}: {v} cases") for k, v in attack_types.items()
        ]))
        
        # Add mitigation suggestions
        if "SYN Flood" in attack_types:
            threat_desc.append(html.P("Mitigation: Enable SYN cookies and rate limiting", className="mt-2 text-info"))
        if "DDoS Attack" in attack_types:
            threat_desc.append(html.P("Mitigation: Contact your DDoS protection service", className="text-info"))
    else:
        threat_desc.append(html.P("No significant threats detected", className="text-success"))
    
    return create_gauge(avg_prob), threat_desc

# ======================
# RUN APPLICATION
# ======================
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8050)
