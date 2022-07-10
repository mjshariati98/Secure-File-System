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
        if p == ".":
            continue
        if file_tree['type'] != 'folder':
            raise Exception(f"{file_tree['name']} is not a folder")
        file_tree = [x for x in file_tree['files'] if x['name'] == p][0]
    return file_tree


def create_directory(file_tree, path):
    path_parts = path_to_parts(path)
    for p in path_parts:
        if file_tree['type'] != 'folder':
            raise Exception(f"{file_tree['name']} is not a folder")
        l = [x for x in file_tree['files'] if x['name'] == p]
        if len(l) == 0:
            nd = {
                "type": "folder",
                "name": p,
                "files": [],
            }
            file_tree['files'].append(nd)
            file_tree = nd
        else:
            file_tree = l[0]
    return file_tree
