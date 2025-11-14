{ ... }:
lib: previousLib: {
  types = previousLib.types // {
    credential = lib.types.either lib.types.path (
      lib.types.submodule {
        options = {
          name = lib.mkOption {
            type = lib.types.string;
            description = "credential name";
          };
          path = lib.mkOption {
            type = lib.types.path;
            description = "credential path";
          };
        };
      }
    );
  };
  systemd = {
    serviceConfig = {
      loadCredential =
        defaultName: value:
        if lib.types.path.check value then
          {
            LoadCredential = [ "${defaultName}:${value}" ];
          }
        else
          {
            LoadCredentialEncrypted = [ value.path ];
          };
    };
  };
}
