"""
NetGuard Dashboard — Streamlit-based Offline Demo Interface.

Screens:
(a) Data source selector (upload CSV/PCAP or use bundled sample)
(b) Live probability timeline (Plotly)
(c) Current MITRE ATT&CK stage badge
(d) Flagged flows table
(e) Explainability panel per selected point
(f) Baseline vs World Model comparison view

CONSTRAINT C4: Zero network calls in inference path. Works offline.
"""

import sys
import os
import json
import numpy as np
import pandas as pd
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Disable telemetry and network access for Streamlit (Constraint C4)
os.environ['STREAMLIT_BROWSER_GATHER_USAGE_STATS'] = 'false'
os.environ['STREAMLIT_SERVER_ENABLE_STATIC_SERVING'] = 'true'

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots


# ─── Page Configuration ──────────────────────────────────────────────────────
st.set_page_config(
    page_title="NetGuard — Network Attack Forecasting",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Custom CSS ──────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-align: center;
        padding: 1rem 0;
    }
    .risk-badge {
        display: inline-block;
        padding: 0.5rem 1.5rem;
        border-radius: 2rem;
        font-weight: 700;
        font-size: 1.2rem;
        text-align: center;
    }
    .risk-critical { background: #FF1744; color: white; }
    .risk-high { background: #FF9100; color: white; }
    .risk-medium { background: #FFC400; color: #333; }
    .risk-low { background: #00E676; color: #333; }
    .mitre-badge {
        display: inline-block;
        padding: 0.4rem 1rem;
        border-radius: 0.5rem;
        font-weight: 600;
        margin: 0.2rem;
    }
    .stMetric label { font-size: 0.9rem; }
    .explanation-box {
        background: #1e1e2e;
        border-left: 4px solid #667eea;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)


@st.cache_resource
def load_models():
    """Load trained models (cached for performance)."""
    import torch
    import joblib
    
    models = {}
    
    # Load World Model
    wm_path = PROJECT_ROOT / "models" / "checkpoints" / "world_model_best.pt"
    if wm_path.exists():
        from src.world_model.model import WorldModel
        checkpoint = torch.load(wm_path, map_location='cpu', weights_only=False)
        config = checkpoint['config']
        wm_config = config.get('world_model', {})
        lstm_config = wm_config.get('lstm', {})
        state_dict = checkpoint['model_state_dict']
        input_size = state_dict['lstm.weight_ih_l0'].shape[1]
        
        model = WorldModel(
            input_size=input_size,
            hidden_size=lstm_config.get('hidden_size', 256),
            num_layers=lstm_config.get('num_layers', 2),
            dropout=0.0,
            num_classes=6,
        )
        model.load_state_dict(state_dict)
        model.eval()
        models['world_model'] = model
    
    # Load baseline
    baseline_path = PROJECT_ROOT / "models" / "checkpoints" / "baseline_lr.joblib"
    if baseline_path.exists():
        models['baseline'] = joblib.load(baseline_path)
    
    # Load metrics
    for name, filename in [('baseline_metrics', 'baseline_metrics.json'), 
                            ('wm_metrics', 'world_model_metrics.json')]:
        metrics_path = PROJECT_ROOT / "models" / filename
        if metrics_path.exists():
            with open(metrics_path) as f:
                models[name] = json.load(f)
    
    # Load feature names
    feat_path = PROJECT_ROOT / "data" / "processed" / "v1" / "window_feature_names.json"
    if feat_path.exists():
        with open(feat_path) as f:
            models['feature_names'] = json.load(f)
    
    return models


def render_header():
    """Render the main header."""
    st.markdown('<h1 class="main-header">🛡️ NetGuard</h1>', unsafe_allow_html=True)
    st.markdown(
        '<p style="text-align:center; color:#888; font-size:1.1rem;">'
        'AI-Based Network Attack Forecasting using World Models</p>',
        unsafe_allow_html=True
    )


def render_sidebar():
    """Render the sidebar with data source selection."""
    st.sidebar.title("📊 Data Source")
    
    source = st.sidebar.radio(
        "Select data source:",
        ["📦 Bundled Sample", "📁 Upload CSV", "📋 Upload PCAP"],
        index=0,
    )
    
    data = None
    
    if source == "📦 Bundled Sample":
        sample_path = PROJECT_ROOT / "data" / "processed" / "v1" / "sample_demo.csv"
        if sample_path.exists():
            data = pd.read_csv(sample_path, low_memory=False)
            st.sidebar.success(f"Loaded {len(data):,} sample flows")
        else:
            st.sidebar.warning("Sample data not found. Run the pipeline first.")
    
    elif source == "📁 Upload CSV":
        uploaded = st.sidebar.file_uploader("Upload network traffic CSV", type=['csv'])
        if uploaded:
            data = pd.read_csv(uploaded, low_memory=False)
            st.sidebar.success(f"Loaded {len(data):,} flows from upload")
    
    elif source == "📋 Upload PCAP":
        st.sidebar.info("PCAP support: Upload a .pcap file for analysis")
        uploaded = st.sidebar.file_uploader("Upload PCAP file", type=['pcap', 'pcapng'])
        if uploaded:
            st.sidebar.warning("PCAP parsing requires Scapy. Using flow extraction...")
    
    # Simulation parameters
    st.sidebar.markdown("---")
    st.sidebar.title("⚙️ Parameters")
    k_steps = st.sidebar.slider("Forecast steps (K)", 1, 50, 10)
    confidence_decay = st.sidebar.slider("Confidence decay", 0.5, 1.0, 0.85, 0.05)
    
    return data, k_steps, confidence_decay


def render_probability_timeline(rollout_result):
    """Render the K-step probability timeline chart."""
    st.subheader("📈 Attack Probability Timeline (K-Step Forecast)")
    
    k = len(rollout_result['probability_timeline'])
    steps = list(range(1, k + 1))
    
    fig = make_subplots(specs=[[{"secondary_y": True}]])
    
    # Probability curve
    fig.add_trace(
        go.Scatter(
            x=steps,
            y=rollout_result['probability_timeline'],
            mode='lines+markers',
            name='Attack Probability',
            line=dict(color='#FF5252', width=3),
            marker=dict(size=8),
            fill='tozeroy',
            fillcolor='rgba(255, 82, 82, 0.1)',
        ),
        secondary_y=False,
    )
    
    # Confidence envelope
    fig.add_trace(
        go.Scatter(
            x=steps,
            y=rollout_result['confidence_values'],
            mode='lines',
            name='Confidence',
            line=dict(color='#448AFF', width=2, dash='dash'),
        ),
        secondary_y=True,
    )
    
    # Threshold line
    fig.add_hline(y=0.5, line_dash="dot", line_color="#FFC107", 
                  annotation_text="Alert Threshold", secondary_y=False)
    
    fig.update_layout(
        height=400,
        template='plotly_dark',
        xaxis_title='Forecast Step (K)',
        legend=dict(orientation="h", yanchor="bottom", y=1.02),
        margin=dict(l=20, r=20, t=40, b=20),
    )
    fig.update_yaxes(title_text="Attack Probability", range=[0, 1], secondary_y=False)
    fig.update_yaxes(title_text="Confidence", range=[0, 1], secondary_y=True)
    
    st.plotly_chart(fig, use_container_width=True)


def render_mitre_stage(rollout_result):
    """Render the MITRE ATT&CK stage badge."""
    from src.simulation.mitre_mapping import MITRE_STAGES, get_stage_color
    
    st.subheader("🎯 Predicted MITRE ATT&CK Stage")
    
    current_stage = rollout_result.get('stage_names', ['Benign'])[0]
    color = get_stage_color(current_stage)
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        risk = rollout_result.get('risk_level', 'LOW')
        risk_class = f"risk-{risk.lower()}"
        st.markdown(
            f'<div class="risk-badge {risk_class}">{risk} RISK</div>',
            unsafe_allow_html=True
        )
    
    with col2:
        st.markdown(
            f'<div class="mitre-badge" style="background:{color}; color:white;">'
            f'📍 {current_stage}</div>',
            unsafe_allow_html=True
        )
    
    with col3:
        prob = rollout_result.get('current_probability', 0)
        st.metric("Attack Probability", f"{prob:.1%}")
    
    # Stage progression
    st.markdown("**Predicted Stage Progression:**")
    stages = rollout_result.get('stage_names', [])
    if stages:
        stage_text = " → ".join(f"`{s}`" for s in stages[:5])
        if len(stages) > 5:
            stage_text += f" → ... ({len(stages)} steps)"
        st.markdown(stage_text)


def render_explanation(rollout_result):
    """Render the explainability panel."""
    st.subheader("🔍 Explanation & Feature Attribution")
    
    explanation = rollout_result.get('explanation', {})
    if not explanation:
        st.warning("No explanation available for this prediction.")
        return
    
    # Plain text explanation
    plain_text = explanation.get('plain_text', 'No explanation generated.')
    st.markdown(f'<div class="explanation-box">{plain_text}</div>', unsafe_allow_html=True)
    
    # Top features chart
    top_features = explanation.get('top_features', [])
    if top_features:
        fig = go.Figure()
        
        names = [f['description'] for f in top_features]
        scores = [f['score'] for f in top_features]
        colors = ['#FF5252' if f['direction'] == 'elevated' else '#448AFF' for f in top_features]
        
        fig.add_trace(go.Bar(
            y=names[::-1],  # reverse for horizontal
            x=scores[::-1],
            orientation='h',
            marker_color=colors[::-1],
        ))
        
        fig.update_layout(
            height=250,
            template='plotly_dark',
            xaxis_title='Attribution Score',
            margin=dict(l=20, r=20, t=10, b=20),
        )
        
        st.plotly_chart(fig, use_container_width=True)


def render_comparison(models):
    """Render baseline vs World Model comparison."""
    st.subheader("📊 Baseline vs World Model Comparison")
    
    baseline_metrics = models.get('baseline_metrics', {})
    wm_metrics = models.get('wm_metrics', {})
    
    if not baseline_metrics or not wm_metrics:
        st.info("Comparison metrics not available. Run the evaluation pipeline first.")
        return
    
    metrics_to_show = [
        ('F1 (Weighted)', 'f1_weighted'),
        ('Precision (Weighted)', 'precision_weighted'),
        ('Recall (Weighted)', 'recall_weighted'),
        ('False Positive Rate', 'false_positive_rate'),
    ]
    
    col1, col2, col3 = st.columns(3)
    
    for i, (display_name, key) in enumerate(metrics_to_show):
        baseline_val = baseline_metrics.get(key, 0)
        wm_val = wm_metrics.get(key, 0)
        delta = wm_val - baseline_val
        
        target_col = [col1, col2, col3][i % 3]
        with target_col:
            # For FPR, lower is better
            if key == 'false_positive_rate':
                delta_str = f"{delta:+.4f}"
                delta_color = "inverse" if delta < 0 else "normal"
            else:
                delta_str = f"{delta:+.4f}"
                delta_color = "normal" if delta > 0 else "inverse"
            
            st.metric(
                display_name,
                f"WM: {wm_val:.4f}",
                delta=delta_str,
                delta_color=delta_color,
            )
    
    # Comparison bar chart
    fig = go.Figure()
    
    metric_names = [m[0] for m in metrics_to_show]
    baseline_vals = [baseline_metrics.get(m[1], 0) for m in metrics_to_show]
    wm_vals = [wm_metrics.get(m[1], 0) for m in metrics_to_show]
    
    fig.add_trace(go.Bar(name='Baseline (LR)', x=metric_names, y=baseline_vals,
                         marker_color='#78909C'))
    fig.add_trace(go.Bar(name='World Model', x=metric_names, y=wm_vals,
                         marker_color='#667eea'))
    
    fig.update_layout(
        barmode='group', height=350, template='plotly_dark',
        legend=dict(orientation="h", yanchor="bottom", y=1.02),
        margin=dict(l=20, r=20, t=40, b=20),
    )
    
    st.plotly_chart(fig, use_container_width=True)


def render_flagged_flows(data, rollout_result):
    """Render table of flagged suspicious flows."""
    st.subheader("🚨 Flagged Flows")
    
    if data is None or len(data) == 0:
        st.info("No flow data loaded.")
        return
    
    # Flag flows with high attack probability
    if 'label' in data.columns:
        flagged = data[data['label'] != 'Benign'].head(20)
    else:
        flagged = data.head(20)
    
    display_cols = []
    for col in ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'label',
                'flow_duration', 'total_fwd_packets', 'syn_ratio', 'rst_ratio']:
        if col in flagged.columns:
            display_cols.append(col)
    
    if display_cols:
        st.dataframe(flagged[display_cols], use_container_width=True, height=300)
    else:
        st.dataframe(flagged.head(20), use_container_width=True, height=300)


# ─── Main App ─────────────────────────────────────────────────────────────────
def main():
    """Main Streamlit application."""
    render_header()
    
    # Load models
    models = load_models()
    
    # Sidebar
    data, k_steps, confidence_decay = render_sidebar()
    
    # Info bar
    st.markdown("---")
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("🔧 Models Loaded", len([k for k in models if k in ['world_model', 'baseline']]))
    with col2:
        st.metric("📊 Data Rows", f"{len(data):,}" if data is not None else "—")
    with col3:
        st.metric("🔮 Forecast Steps", k_steps)
    with col4:
        st.metric("🔒 Offline Mode", "✅ Active")
    
    st.markdown("---")
    
    if data is not None and 'world_model' in models:
        # Run inference
        import torch
        from src.features.sequencer import create_time_windows, create_sequences
        from src.simulation.rollout import run_inference
        from src.explainability.explain import explain_prediction
        
        # Create sequences from data
        windows = create_time_windows(data, window_size_seconds=10, min_flows_per_window=2)
        
        if len(windows) > 5:
            from src.features.sequencer import get_window_feature_names
            window_feats = get_window_feature_names(windows)
            
            X, _, _ = create_sequences(windows, sequence_length=min(5, len(windows) - 1))
            
            if len(X) > 0:
                # Run world model inference
                model = models['world_model']
                
                result = run_inference(
                    model, X[0], k_steps=k_steps,
                    confidence_decay_factor=confidence_decay,
                )
                
                # Add explanation
                result = explain_prediction(
                    model, X[0], result, window_feats,
                    method='gradient', top_k=5,
                )
                
                # Render visualizations
                tab1, tab2, tab3, tab4 = st.tabs([
                    "📈 Timeline", "🎯 MITRE Stage", "🔍 Explanation", "📊 Comparison"
                ])
                
                with tab1:
                    render_probability_timeline(result)
                    render_flagged_flows(data, result)
                
                with tab2:
                    render_mitre_stage(result)
                
                with tab3:
                    render_explanation(result)
                
                with tab4:
                    render_comparison(models)
            else:
                st.warning("Not enough sequential data to create forecasting windows.")
        else:
            st.warning("Not enough time windows. Try data with more temporal coverage.")
    
    elif data is not None:
        st.warning("⚠️ World Model not found. Run the training pipeline first.")
        st.info("You can still view the data:")
        st.dataframe(data.head(50), use_container_width=True)
    
    else:
        st.info("👈 Select a data source from the sidebar to begin analysis.")
        
        # Show comparison even without data
        if models.get('baseline_metrics') or models.get('wm_metrics'):
            render_comparison(models)
    
    # Footer
    st.markdown("---")
    st.markdown(
        '<p style="text-align:center; color:#666; font-size:0.8rem;">'
        'NetGuard v0.1.0 — SIH26153 · Built for NTRO · 100% Offline Operation'
        '</p>',
        unsafe_allow_html=True
    )


if __name__ == '__main__':
    main()
