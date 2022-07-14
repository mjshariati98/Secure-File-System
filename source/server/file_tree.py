def default_file_tree():
    return {
        "type": "folder",
        "name": "~",
        "files": [],
    }


def path_to_parts(path):
    path_parts = path.split("/")
    assert path_parts[0] == '~'
    return path_parts[1:]


def locate_path(file_tree, path):
    path_parts = path_to_parts(path)
    for p in path_parts:
        if p == "." or p == "":
            continue
        if file_tree['type'] != 'folder':
            raise Exception(f"{file_tree['name']} is not a folder")
        file_tree = [x for x in file_tree['files'] if x['name'] == p][0]
    return file_tree


def set_file_name(file_tree, path, fs_file_name):
    path_parts = path_to_parts(path)
    name = path_parts[-1]
    path_parts = path_parts[:-1]
    for p in path_parts:
        if file_tree['type'] != 'folder':
            raise Exception(f"{file_tree['name']} is not a folder")
        file_tree_list = [x for x in file_tree['files'] if x['name'] == p]
        if len(file_tree_list) == 0:
            new_folder = {
                "type": "folder",
                "name": p,
                "files": [],
            }
            file_tree['files'].append(new_folder)
            file_tree = new_folder
        else:
            file_tree = file_tree_list[0]
    file_tree_list = [x for x in file_tree['files'] if x['name'] == name]
    if len(file_tree_list) == 0:  # there is no file with name equals to `name`
        new_file = {
            "type": "file",
            "name": name,
            "content": fs_file_name,
        }
        file_tree['files'].append(new_file)
    else:
        file_tree_list[0]['content'] = fs_file_name



def create_directory(file_tree, path):
    path_parts = path_to_parts(path)
    for p in path_parts:
        if file_tree['type'] != 'folder':
            raise Exception(f"{file_tree['name']} is not a folder")
        file_tree_list = [x for x in file_tree['files'] if x['name'] == p]
        if len(file_tree_list) == 0:  # there is no directory with name equals to `p`
            new_folder = {
                "type": "folder",
                "name": p,
                "files": [],
            }
            file_tree['files'].append(new_folder)
            file_tree = new_folder
        else:
            file_tree = file_tree_list[0]
