import dash
import os
import dash_core_components as dcc
import dash_html_components as html
import dash_bootstrap_components as dbc
from dash.dependencies import Input, Output, State
from enc_files.enc_manager import EncDecManager

external_stylesheets = [dbc.themes.JOURNAL, 'https://codepen.io/chriddyp/pen/bWLwgP.css']

app = dash.Dash(__name__, external_stylesheets=external_stylesheets)

app.layout = html.Div(
    [
        html.Div([
            html.P("path"),
            dcc.Input(
                id="in_path",
                type="text",
                autoComplete="on",

            ), ], style={'display': "inline-block"}),
        html.Div([
            html.P("pass"),
            dcc.Input(
                id="in_pass",
                type="password",
                debounce=True,
            ), ], style={'display': "inline-block"}),
        html.Div([
            html.Button(id='submit-button-state', n_clicks=0, children='Submit')],
            style={'display': 'inline-block'}),
        html.Div([
            dbc.Alert(
                children="Hello! I am an alert",
                id="alerts",
                color="danger",
                dismissable=True,
                is_open=False, )],
            style={'display': "inline-block"}),
        html.Div([
            html.Div([
                html.Button(id='enc-folders-button', n_clicks=0, children='Encrypt folders')],
                style={'display': 'inline-block'}),
            html.Div([
                html.Button(id='dec-folders-button', n_clicks=0, children='Decrypt folders')],
                style={'display': 'inline-block'}),
            html.Div([
                html.Button(id='enc-all-button', n_clicks=0, children='Encrypt all Files')],
                style={'display': 'inline-block'}),
            html.Div([
                html.Button(id='dec-all-button', n_clicks=0, children='Decrypt all Files')],
                style={'display': 'inline-block'}),
            html.Div([
                html.Button(id='del_enc_version-button', n_clicks=0, children='Delete encrypted version')],
                style={'display': 'inline-block'}),
        ]),
        html.Div([
            html.Div([
                html.Button(id='enc-dec-selected-button', n_clicks=0, children='Encrypt/Dycrypt selected'),
            ],
                style={'display': 'inline-block'}),
            html.Div([dcc.Checklist(id="delete-old",
                                    options=[{'label': 'Delete converted files?  ', 'value': "yes"}], )],
                     style={'display': 'inline-block'}),
        ]),
        html.Div([
            html.P("Normal files"),
            dcc.Checklist(
                id='opt-checklist-dec',
            ),
            html.P("Encrypted files"),
            dcc.Checklist(
                id='opt-checklist-enc',
            )
        ], style={'display': "inline-block"}
        ),
        html.Hr(),
        html.Div(id='display-selected-values'),
    ]
)


def get_manager(path_name, password) -> EncDecManager:
    if password and path_name and os.path.isdir(path_name):
        manager = EncDecManager(password.encode("utf8"), workers=2, verbose=False, make_hidden=True)
        manager.scan_path(path_name)
        return manager
    return None


def get_names(path_name, password, names, manager_in=None):
    res_dict = {}
    for n in names:
        res_dict[n] = {}
    manager = manager_in if manager_in else get_manager(path_name, password)
    if manager:
        try:
            types = manager.split_to_types(prepare_all_names=True)
            for n in names:
                res_dict[n] = {f.real_path: {"id": f.id, "name": f.dec_name,
                                             "size": os.stat(f.real_path).st_size / (1024 * 1024) if os.path.isfile(
                                                 f.real_path) else 0} for f in types[n]}
        except ValueError as err:
            res_dict['error'] = str(err)

    return res_dict


@app.callback(
    [Output('opt-checklist-enc', 'options'),
     Output('opt-checklist-dec', 'options'),
     Output('opt-checklist-dec', 'value'),
     Output('opt-checklist-enc', 'value'),
     Output("alerts", "is_open"),
     Output('alerts', 'children'),
     # Output('display-selected-values', 'children'),
     ],
    [Input('submit-button-state', 'n_clicks'),
     Input('enc-folders-button', 'n_clicks'),
     Input('dec-folders-button', 'n_clicks'),
     Input('enc-dec-selected-button', 'n_clicks'),
     Input('enc-all-button', 'n_clicks'),
     Input('dec-all-button', 'n_clicks'),
     Input('del_enc_version-button', 'n_clicks'),
     Input('in_pass', 'value'),
     ],
    [State('in_path', 'value'),
     State('in_pass', 'value'),
     State('delete-old', 'value'),
     State('opt-checklist-dec', 'value'),
     State('opt-checklist-enc', 'value')]
)
def update_date_dropdown(submit_btn_n, enc_folders_btn_n, dec_folders_btn_n, enc_dec_selected_btn_n, enc_all_btn_n,
                         dec_all_btn_n, del_enc_ver_btn_n, in_pass, path_name, password, delete_old, dec_list,
                         enc_list):
    changed_id = [p['prop_id'] for p in dash.callback_context.triggered][0]

    cur_buttons = {'enc-folders-button': 'norm_folder_list',
                   'dec-folders-button': 'enc_folder_list',
                   'enc-all-button': 'norm_file_list',
                   'dec-all-button': 'enc_file_list',
                   }
    cur_button = [cur_buttons[btn] for btn in cur_buttons.keys() if btn in changed_id]
    if cur_button:
        # encrypt/decrypt all of 1 type - according to whcih button selected
        manager = get_manager(path_name, password)
        if manager:
            work_list = get_names(path_name, password, [cur_button[0]], manager_in=manager)
            manager.end_dec_by_id([i["id"] for i in work_list[cur_button[0]].values()], remove_old=bool(delete_old))

    if 'enc-dec-selected-button' in changed_id:  # for btn in [, 'del_enc_version-button']):
        # encrypt and decrypt all files selected
        manager = get_manager(path_name, password)
        if manager:
            manager.end_dec_by_paths((dec_list or []) + (enc_list or []), remove_old=bool(delete_old))

    if 'del_enc_version-button' in changed_id:
        # delete all encrypted version or the normal files selected
        manager = get_manager(path_name, password)
        if manager and dec_list:
            dec_set = set(dec_list)
            work_list = get_names(path_name, password, ['enc_file_list'], manager_in=manager)
            work_set = [i for i in work_list['enc_file_list'].values() if i['name'] in dec_set]
            manager.end_dec_by_id([i["id"] for i in work_set], remove_old=True)

    # make the lists view
    res_dict = get_names(path_name, password, ['enc_file_list', 'norm_file_list'])

    enc_list_checklist = [
        {'label': f'{res_dict["enc_file_list"][i]["name"]} ({res_dict["enc_file_list"][i]["size"]:.2f}MB)', 'value': i}
        for i in
        res_dict['enc_file_list']]
    dec_list_checklist = [
        {'label': f'{res_dict["norm_file_list"][i]["name"]} ({res_dict["norm_file_list"][i]["size"]:.2f}MB)',
         'value': i} for i
        in res_dict['norm_file_list']]
    if "error" in res_dict:
        print(res_dict['error'])
        alert_message = res_dict['error']
    else:
        alert_message = ""
    return enc_list_checklist, dec_list_checklist, [], [], "error" in res_dict, alert_message


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
    app.run_server(debug=False, port=8056, host='0.0.0.0')
