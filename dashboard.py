import dash
import os
import dash_core_components as dcc
import dash_html_components as html
from dash.dependencies import Input, Output, State
from enc_files.enc_manager import EncDecManager


external_stylesheets = ['https://codepen.io/chriddyp/pen/bWLwgP.css']

app = dash.Dash(external_stylesheets=external_stylesheets)

app.layout = html.Div(
    [
        html.Div([
            html.P("path"),
            dcc.Input(
                id="in_path",
                type="text",
            ), ], style={'display': "inline-block"}),
        html.Div([
            html.P("pass"),
            dcc.Input(
                id="in_pass",
                type="password",
            ), ], style={'display': "inline-block"}),
        html.Div([
            html.Button(id='submit-button-state', n_clicks=0, children='Submit')],
            style={'display': 'inline-block'}),
        html.Div([
            html.Div([
                html.Button(id='enc-dec-selected-button', n_clicks=0, children='Encrypt/Dycrypt selected'),
            ],
                style={'display': 'inline-block'}),
            html.Div([dcc.Checklist(id="delete-old",
                                    options=[{'label': 'Delete converted files?  ', 'value': "yes"}],)],
                     style={'display': 'inline-block'}),
            html.Div([
                html.Button(id='enc-folders-button', n_clicks=0, children='Encrypt folders')],
                style={'display': 'inline-block'}),
            html.Div([
                html.Button(id='dec-folders-button', n_clicks=0, children='Decrypt folders')],
                style={'display': 'inline-block'}),
        ]),
        html.Div([
            html.P("Normal files"),
            dcc.Checklist(
                id='opt-checklist-dec',
                value=[],
                persistence=True,
            ),
            html.P("Encrypted files"),
            dcc.Checklist(
                id='opt-checklist-enc',
                value=[],
                persistence=True,
            )
        ], style={"width": '100%', 'display': "inline-block"}
        ),
        html.Hr(),
        html.Div(id='display-selected-values'),

    ]
)


def get_manager(path_name, password) -> EncDecManager:
    if password and path_name and os.path.isdir(path_name):
        manager = EncDecManager(password.encode("utf8"), workers=2, verbose=False)
        manager.scan_path(path_name)
        return manager
    return None


def get_names(path_name, password, names, manager_in=None):
    res_dict = {}
    for n in names:
        res_dict[n] = {}
    manager = manager_in if manager_in else get_manager(path_name, password)
    if manager:
        types = manager.split_to_types(prepare_all_names=True)
        for n in names:
            res_dict[n] = {f.real_path: {"id": f.id, "name": f.dec_name} for f in types[n]}
    return res_dict


@app.callback(
    [Output('opt-checklist-enc', 'options'),
     Output('opt-checklist-dec', 'options'),
     Output('opt-checklist-dec', 'value'),
     Output('opt-checklist-enc', 'value'),
     # Output('display-selected-values', 'children'),
     ],
    [Input('submit-button-state', 'n_clicks'),
     Input('enc-folders-button', 'n_clicks'),
     Input('dec-folders-button', 'n_clicks'),
     Input('enc-dec-selected-button', 'n_clicks'),
     ],
    [State('in_path', 'value'),
     State('in_pass', 'value'),
     State('delete-old', 'value'),
     State('opt-checklist-dec', 'value'),
     State('opt-checklist-enc', 'value')]
)
def update_date_dropdown(submit_btn_n, enc_folders_btn_n, dec_folders_btn_n, enc_dec_selected_btn_n, path_name,
                         password, delete_old, dec_list, enc_list):
    changed_id = [p['prop_id'] for p in dash.callback_context.triggered][0]
    submt_btn, enc_folder_btn, dec_folder_btn, enc_dec_selected_btn = False, False, False, False
    if 'submit-button-state' in changed_id:
        submit_btn = True
    if 'enc-folders-button' in changed_id:
        enc_folder_btn = True
    if 'dec-folders-button' in changed_id:
        dec_folder_btn = True
    if 'enc-dec-selected-button' in changed_id:
        enc_dec_selected_btn = True

    if enc_folder_btn:
        manager = get_manager(path_name, password)
        if manager:
            norm_folders = get_names(path_name, password, ['norm_folder_list'], manager_in=manager)
            manager.end_dec_by_id([i["id"] for i in norm_folders['norm_folder_list'].values()])

    if dec_folder_btn:
        manager = get_manager(path_name, password)
        if manager:
            enc_folders = get_names(path_name, password, ['enc_folder_list'], manager_in=manager)
            manager.end_dec_by_id([i["id"] for i in enc_folders['enc_folder_list'].values()])

    if enc_dec_selected_btn:
        print(dec_list)
        print(enc_list)
        manager = get_manager(path_name, password)
        if manager:
            manager.end_dec_by_paths((dec_list or []) + (enc_list or []), remove_old=bool(delete_old))

    res_dict = get_names(path_name, password, ['enc_file_list', 'norm_file_list'])

    enc_list_checklist = [
        {'label': f'{res_dict["enc_file_list"][i]["name"]} ({res_dict["enc_file_list"][i]["id"]})', 'value': i} for i in
        res_dict['enc_file_list']]
    dec_list_checklist = [
        {'label': f'{res_dict["norm_file_list"][i]["name"]} ({res_dict["norm_file_list"][i]["id"]})', 'value': i} for i
        in res_dict['norm_file_list']]
    return enc_list_checklist, dec_list_checklist, [], []


@app.callback(
    Output('display-selected-values', 'children'),
    [Input('opt-checklist-dec', 'value'),
     Input('opt-checklist-enc', 'value'),
     ])
def set_display_children(dec_list, enc_list):
    if enc_list is None:
        return html.Div([
            html.P('No Encrypted file names chosen:')])
    return html.Div([
        html.P('Encrypted file names chosen:'),
        html.Div([html.P(i) for i in enc_list]),
    ])


if __name__ == '__main__':
    app.run_server(port=8055)
