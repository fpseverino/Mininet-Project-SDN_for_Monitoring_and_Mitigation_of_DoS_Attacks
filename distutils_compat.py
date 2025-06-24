# Compatibility layer for distutils.version on Python 3.13+
from packaging import version

class LooseVersion:
    """Compatibility wrapper for distutils.version.LooseVersion"""
    def __init__(self, vstring):
        self.version = version.parse(str(vstring))
        self.vstring = vstring
    
    def __str__(self):
        return self.vstring
    
    def __repr__(self):
        return f"LooseVersion ('{self.vstring}')"
    
    def __eq__(self, other):
        if isinstance(other, LooseVersion):
            return self.version == other.version
        return self.version == version.parse(str(other))
    
    def __lt__(self, other):
        if isinstance(other, LooseVersion):
            return self.version < other.version
        return self.version < version.parse(str(other))
    
    def __le__(self, other):
        return self == other or self < other
    
    def __gt__(self, other):
        return not self <= other
    
    def __ge__(self, other):
        return not self < other
    
    def __ne__(self, other):
        return not self == other

class StrictVersion:
    """Compatibility wrapper for distutils.version.StrictVersion"""
    def __init__(self, vstring):
        self.version = version.parse(str(vstring))
        self.vstring = vstring
    
    def __str__(self):
        return self.vstring
    
    def __repr__(self):
        return f"StrictVersion ('{self.vstring}')"
    
    def __eq__(self, other):
        if isinstance(other, StrictVersion):
            return self.version == other.version
        return self.version == version.parse(str(other))
    
    def __lt__(self, other):
        if isinstance(other, StrictVersion):
            return self.version < other.version
        return self.version < version.parse(str(other))
    
    def __le__(self, other):
        return self == other or self < other
    
    def __gt__(self, other):
        return not self <= other
    
    def __ge__(self, other):
        return not self < other
    
    def __ne__(self, other):
        return not self == other

# Monkey patch distutils if it doesn't exist
import sys
try:
    import distutils.version
except ImportError:
    # Create a fake distutils module
    import types
    distutils = types.ModuleType('distutils')
    distutils.version = types.ModuleType('distutils.version')
    distutils.version.LooseVersion = LooseVersion
    distutils.version.StrictVersion = StrictVersion
    sys.modules['distutils'] = distutils
    sys.modules['distutils.version'] = distutils.version
